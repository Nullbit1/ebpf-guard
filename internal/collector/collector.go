package collector

import (
    "bytes"
    "context"
    "encoding/binary"
    "errors"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "path/filepath"
    "syscall"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "golang.org/x/sys/unix"

    "github.com/your-org/ebpf-guard/internal/alerts"
    "github.com/your-org/ebpf-guard/internal/detect"
    "github.com/your-org/ebpf-guard/internal/metrics"
    "github.com/your-org/ebpf-guard/internal/model"
)

type Collector struct {
    bpfObjectPath string
}

func New(bpfObjectPath string) *Collector {
    return &Collector{bpfObjectPath: bpfObjectPath}
}

type rawEvent struct {
    TsNs      uint64
    Pid       uint32
    Tgid      uint32
    EventType uint32
    DestPort  uint16
    Pad       uint16
    DestIP4   uint32
    Comm      [16]byte
    Filename  [256]byte
}

func (c *Collector) Run(ctx context.Context, eng *detect.Engine, writer *alerts.FileWriter) error {
    if err := raiseRlimit(); err != nil {
        return err
    }

    bpfPath := c.bpfObjectPath
    if !filepath.IsAbs(bpfPath) {
        exe, err := os.Executable()
        if err != nil {
            return fmt.Errorf("resolve executable: %w", err)
        }
        bpfPath = filepath.Join(filepath.Dir(exe), bpfPath)
    }

    spec, err := ebpf.LoadCollectionSpec(bpfPath)
    if err != nil {
        return fmt.Errorf("load BPF spec from %s: %w", bpfPath, err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        return fmt.Errorf("create BPF collection: %w", err)
    }
    defer coll.Close()

    eventsMap, ok := coll.Maps["events"]
    if !ok {
        return fmt.Errorf("BPF map 'events' not found")
    }

    progExec, ok := coll.Programs["handle_exec"]
    if !ok {
        return fmt.Errorf("BPF program 'handle_exec' not found")
    }
    progOpen, ok := coll.Programs["handle_openat"]
    if !ok {
        return fmt.Errorf("BPF program 'handle_openat' not found")
    }
    progConnect, ok := coll.Programs["handle_connect"]
    if !ok {
        return fmt.Errorf("BPF program 'handle_connect' not found")
    }

    tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", progExec, nil)
    if err != nil {
        return fmt.Errorf("attach execve tracepoint: %w", err)
    }
    defer tpExec.Close()

    tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", progOpen, nil)
    if err != nil {
        return fmt.Errorf("attach openat tracepoint: %w", err)
    }
    defer tpOpen.Close()

    tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", progConnect, nil)
    if err != nil {
        return fmt.Errorf("attach connect tracepoint: %w", err)
    }
    defer tpConnect.Close()

    reader, err := ringbuf.NewReader(eventsMap)
    if err != nil {
        return fmt.Errorf("create ringbuf reader: %w", err)
    }
    defer reader.Close()

    go func() {
        <-ctx.Done()
        reader.Close()
    }()

    log.Printf("ebpf-guard started with BPF object %s", bpfPath)

    for {
        record, err := reader.Read()
        if err != nil {
            if ctx.Err() != nil {
                return nil
            }
            if errors.Is(err, os.ErrClosed) {
                return nil
            }
            log.Printf("ringbuf read error: %v", err)
            continue
        }

        var re rawEvent
        if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &re); err != nil {
            log.Printf("decode raw event: %v", err)
            continue
        }

        ev := convertRawEvent(re)
        metrics.IncEvent(ev.Type)

        alertsList := eng.Evaluate(ev)
        for _, a := range alertsList {
            metrics.IncAlert(a.RuleID)
            if err := writer.Write(a); err != nil {
                log.Printf("write alert: %v", err)
            }
        }
    }
}

func raiseRlimit() error {
    var r unix.Rlimit
    r.Cur = 1 << 30
    r.Max = 1 << 30
    if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &r); err != nil {
        return fmt.Errorf("setrlimit RLIMIT_MEMLOCK: %w", err)
    }
    return nil
}

func convertRawEvent(re rawEvent) model.Event {
    ts := time.Unix(0, int64(re.TsNs)).UTC()
    comm := cString(re.Comm[:])
    filename := cString(re.Filename[:])

    var destIP string
    if re.DestIP4 != 0 {
        var b [4]byte
        binary.LittleEndian.PutUint32(b[:], re.DestIP4)
        destIP = net.IP(b[:]).String()
    }

    var destPort uint16
    if re.DestPort != 0 {
        lo := byte(re.DestPort & 0xff)
        hi := byte(re.DestPort >> 8)
        destPort = uint16(hi)<<8 | uint16(lo)
    }

    var et model.EventType
    switch re.EventType {
    case 0:
        et = model.EventExec
    case 1:
        et = model.EventOpen
    case 2:
        et = model.EventConnect
    default:
        et = model.EventType("unknown")
    }

    return model.Event{
        Timestamp: ts,
        Pid:       re.Pid,
        Tgid:      re.Tgid,
        Type:      et,
        Comm:      comm,
        Filename:  filename,
        DestIP:    destIP,
        DestPort:  destPort,
    }
}

func cString(b []byte) string {
    n := bytes.IndexByte(b, 0)
    if n == -1 {
        n = len(b)
    }
    return string(b[:n])
}

func WithSignalCancel(parent context.Context) (context.Context, context.CancelFunc) {
    ctx, cancel := context.WithCancel(parent)
    ch := make(chan os.Signal, 1)
    signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        defer signal.Stop(ch)
        select {
        case <-ch:
            cancel()
        case <-ctx.Done():
        }
    }()

    return ctx, cancel
}
