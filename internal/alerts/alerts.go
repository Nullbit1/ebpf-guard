package alerts

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "sync"

    "github.com/your-org/ebpf-guard/internal/detect"
)

type FileWriter struct {
    mu      sync.Mutex
    f       *os.File
    encoder *json.Encoder
}

func NewFileWriter(path string) (*FileWriter, error) {
    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
    if err != nil {
        return nil, fmt.Errorf("open alert file: %w", err)
    }
    return &FileWriter{
        f:       f,
        encoder: json.NewEncoder(f),
    }, nil
}

func (w *FileWriter) Close() error {
    w.mu.Lock()
    defer w.mu.Unlock()
    if w.f == nil {
        return nil
    }
    err := w.f.Close()
    w.f = nil
    return err
}

func (w *FileWriter) Write(a detect.Alert) error {
    w.mu.Lock()
    defer w.mu.Unlock()

    if w.f == nil {
        return fmt.Errorf("alert writer closed")
    }

    if err := w.encoder.Encode(a); err != nil {
        return fmt.Errorf("encode alert: %w", err)
    }

    log.Printf("[ALERT] rule=%s comm=%s filename=%s pid=%d",
        a.RuleID, a.Event.Comm, a.Event.Filename, a.Event.Pid)

    return nil
}
