# ebpf-guard - eBPF based runtime threat detector for Linux

`ebpf-guard` is a small runtime detector made of two parts:

* a C eBPF program that hooks a few syscall tracepoints
* a Go daemon that pulls events from a ring buffer, runs detection rules and emits alerts and Prometheus metrics

The idea is simple: watch what processes do on the box in real time and scream when something obviously bad happens, without dragging in a huge framework.

Typical things you can catch:

* fileless and memory backed execution
* suspicious shells on production nodes
* executables that look like crypto miners
* outbound connections on common mining ports

Everything is local on the host. No agents in containers, no external backend.

---

## What ebpf-guard watches

The BPF side is in `internal/bpf/ebpf_guard.bpf.c`. It attaches to three syscall tracepoints:

* `tracepoint/syscalls/sys_enter_execve`
* `tracepoint/syscalls/sys_enter_openat`
* `tracepoint/syscalls/sys_enter_connect`

For each hit it builds a compact event and pushes it to a ring buffer map called `events`.
On the Go side this is exposed as the following model (see `internal/model/model.go`):

```go
type EventType string

const (
    EventExec    EventType = "exec"
    EventOpen    EventType = "open"
    EventConnect EventType = "connect"
)

type Event struct {
    Timestamp time.Time `json:"timestamp"`
    Pid       uint32    `json:"pid"`
    Tgid      uint32    `json:"tgid"`
    Type      EventType `json:"type"`

    Comm     string `json:"comm"`      // task comm (short name)
    Filename string `json:"filename"`  // exec path, open path or "connect"

    DestIP   string `json:"dest_ip,omitempty"`   // set only for connect events
    DestPort uint16 `json:"dest_port,omitempty"` // set only for connect events
}
```

So for every interesting syscall you get:

* process identifiers
* the command and file name
* for connects: destination IPv4 address and port

These events never leave the host. Only alerts are written to disk and exported via metrics.

---

## High level architecture

A rough picture:

```text
   [syscalls]          [eBPF program]           [Go daemon]                  [outputs]
exec / open / connect  -> tracepoints -> ringbuf -> collector -> detector -> metrics + alerts.jsonl

                                       ^
                                       |
                                  rules.yaml
```

More concretely:

1. The BPF program attaches to syscall tracepoints and writes `struct event` into the `events` ring buffer.

2. `internal/collector` loads `ebpf_guard.bpf.o` with `github.com/cilium/ebpf`, attaches the three probe programs and starts a ring buffer reader.

3. Each raw event is converted into a `model.Event` and fed into `internal/detect.Engine`.

4. The engine:

   * always applies a set of built in heuristics
   * then applies all user defined rules from the YAML config

   For each match it returns an `Alert`:

   ```go
   type Alert struct {
       Timestamp   time.Time       `json:"timestamp"`
       RuleID      string          `json:"rule_id"`
       Description string          `json:"description"`
       EventType   model.EventType `json:"event_type"`
       Event       model.Event     `json:"event"`
   }
   ```

5. `internal/alerts.FileWriter` appends each alert as one JSON object per line (JSONL) and logs a short human readable message.

6. `internal/metrics` bumps counters for events and alerts and exposes them via `/metrics` for Prometheus.

---

## Requirements

### Kernel and OS

* Linux with eBPF and tracepoints enabled
* Tracepoints:

  * `syscalls:sys_enter_execve`
  * `syscalls:sys_enter_openat`
  * `syscalls:sys_enter_connect`
* Recommended:

  * kernel 5.4 or newer
  * BPF ring buffer support

### Privileges

To load and attach eBPF programs you need:

* root, or
* at least `CAP_BPF` and `CAP_SYS_ADMIN` (and enough `RLIMIT_MEMLOCK`)

The `collector` raises `RLIMIT_MEMLOCK` at startup so that the BPF maps can be pinned in memory.

### Toolchain

Build time:

* Go 1.21 or newer
* Clang with BPF target for compiling `ebpf_guard.bpf.c`

Run time:

* the compiled `ebpf_guard.bpf.o` file
* the `ebpf-guard` Go binary

No separate service dependencies. Metrics are sent over HTTP locally, alerts are written to a file.

---

## Building

Clone the repository and build both parts.

```bash
git clone https://github.com/Nullbit1/ebpf-guard.git
cd ebpf-guard
```

### 1. Build the eBPF object

There is a small Makefile in `internal/bpf`:

```bash
cd internal/bpf
make
```

This will:

* call `clang` with `-target bpf`
* compile `ebpf_guard.bpf.c` into `ebpf_guard.bpf.o` in the same directory

You can override the compiler or flags:

```bash
make BPF_CLANG=clang-18
make BPF_CFLAGS='-O2 -g -Wall -target bpf -DDEBUG=1'
```

If you do not want to run `make` manually in production, you can ship the built `ebpf_guard.bpf.o` alongside the `ebpf-guard` binary.

### 2. Build the Go daemon

From the repo root:

```bash
go mod tidy
go build ./cmd/ebpf-guard
```

This produces an `ebpf-guard` binary in the current directory.

By default the binary expects the BPF object at:

```text
./internal/bpf/ebpf_guard.bpf.o
```

relative to the binary, but you can override the path at runtime with `-bpf-object`.

---

## YAML rules configuration

Detection rules are provided as a YAML file.
There is a small example at `config/rules.example.yaml`:

```yaml
rules:
  - id: suspicious_shell
    description: Suspicious shell execution
    event_types: ["exec"]
    comm_regex: "(?i)(bash|sh|zsh|ksh|dash)"

  - id: crypto_miner_exec
    description: Executable name looks like a crypto miner
    event_types: ["exec"]
    filename_regex: "(?i)(xmrig|minerd|cryptominer)"

  - id: crypto_miner_port
    description: Outgoing connection to common mining pool ports (rough heuristic)
    event_types: ["connect"]
    min_dest_port: 3333
    max_dest_port: 5555
```

### Schema

Each rule has this shape (see `internal/config/config.go`):

```yaml
rules:
  - id: string                      # required, unique per rule set
    description: string             # required, free text

    event_types:                    # required, at least one
      - "exec"                      # or "open" or "connect"

    comm_regex: "..."               # optional, Go regexp, matches Event.Comm
    filename_regex: "..."           # optional, Go regexp, matches Event.Filename

    min_dest_port: 0                # optional, only meaningful for connect events
    max_dest_port: 65535            # optional, only meaningful for connect events
```

Behaviour:

* `event_types`
  At least one of `exec`, `open`, `connect`. If you pass something else, the engine will refuse to start and print a clear error.

* `comm_regex`
  If set, the rule only fires when the regular expression matches `Event.Comm`.
  For example to catch shells:

  ```yaml
  comm_regex: "(?i)(bash|sh|zsh|ksh|dash)"
  ```

* `filename_regex`
  If set, the rule only fires when the regular expression matches `Event.Filename`.
  For example to catch files that look like miners:

  ```yaml
  filename_regex: "(?i)(xmrig|minerd|cryptominer)"
  ```

* `min_dest_port` and `max_dest_port`
  These are optional integer bounds.
  If present, they are applied to `Event.DestPort` for connect events:

  * if `min_dest_port` is set and `DestPort < min_dest_port` the rule is skipped
  * if `max_dest_port` is set and `DestPort > max_dest_port` the rule is skipped

You can combine the conditions. For example, a rule that fires only on SSH traffic coming from a specific binary name could use:

```yaml
rules:
  - id: ssh_odd_port
    description: SSH like binary talking on high port
    event_types: ["connect"]
    filename_regex: "(?i)ssh"
    min_dest_port: 20000
```

### Engine behaviour

For each incoming event, the engine:

1. Adds alerts from built in heuristics (see below).

2. Walks all compiled rules and for each rule:

   * checks if the event type is in `event_types`
   * applies `comm_regex` if present
   * applies `filename_regex` if present
   * applies `min_dest_port` and `max_dest_port` if present

3. For every rule that passes all checks it emits an `Alert` with:

   * `rule_id` set to the YAML id
   * `description` copied from the YAML
   * `event` containing the original event

There is no built in deduplication between rules. If multiple rules match the same event, you will get multiple alerts.

---

## Running the daemon

The main binary lives in `cmd/ebpf-guard`. It exposes a small CLI in `main.go`.

Flags:

```go
bpfObject  = flag.String("bpf-object", "./internal/bpf/ebpf_guard.bpf.o", "Path to compiled eBPF object file")
configPath = flag.String("config", "./config/rules.example.yaml", "Path to YAML rules configuration")
promAddr   = flag.String("prom-addr", ":9100", "Address for Prometheus metrics (for example :9100)")
alertFile  = flag.String("alert-file", "./alerts.jsonl", "Path to JSON lines alert file")
```

Minimal example (run as root or with appropriate caps):

```bash
sudo ./ebpf-guard \
  -bpf-object ./internal/bpf/ebpf_guard.bpf.o \
  -config ./config/rules.example.yaml \
  -prom-addr :9100 \
  -alert-file ./alerts.jsonl
```

What happens here:

* the BPF object is loaded and programs are attached to syscall tracepoints
* a ring buffer reader starts pulling raw events from the `events` map
* the detection engine evaluates built in and YAML rules for each event
* alerts are appended to `./alerts.jsonl` as one JSON object per line
* metrics are exposed on `http://localhost:9100/metrics`

The process listens for `SIGINT` and `SIGTERM` and will exit cleanly when you hit Ctrl+C.

---

## Alert format and example

Alerts are written as JSONL, one per line, via `internal/alerts.FileWriter`.

Example entry:

```json
{
  "timestamp": "2025-01-01T12:00:00Z",
  "rule_id": "builtin_fileless_exec",
  "description": "Fileless or memory-backed executable",
  "event_type": "exec",
  "event": {
    "timestamp": "2025-01-01T12:00:00Z",
    "pid": 4242,
    "tgid": 4242,
    "type": "exec",
    "comm": "bash",
    "filename": "/dev/shm/.x",
    "dest_ip": "",
    "dest_port": 0
  }
}
```

At the same time, the daemon logs a short line to stdout:

```text
[ALERT] rule=builtin_fileless_exec comm=bash filename=/dev/shm/.x pid=4242
```

You can tail `alerts.jsonl` directly, push it into Loki, ship it with `fluent-bit` or feed it to your own scripts.

---

## Built in heuristics

Even if you provide an empty YAML file, the following built in detectors are always enabled in `builtinHeuristics`:

* `builtin_fileless_exec`
  Fires on `exec` events where `filename` looks like:

  * `memfd:*`
  * under `/dev/shm/`
  * under `/tmp/.`
  * under `/proc/self/fd/`

* `builtin_suspicious_shell`
  Fires on `exec` events where the command name looks like a shell. The helper `looksLikeShell` checks lowercased strings for:

  * `bash`
  * exactly `sh`
  * `zsh`, `ksh`, `dash`

* `builtin_crypto_exec`
  Fires on `exec` events where `filename` or `comm` match common crypto miner patterns (xmrig, minerd and similar, see the code for the exact list).

* `builtin_crypto_port`
  Fires on `connect` events where the destination port is one of the common mining ports:

  * 3333
  * 4444
  * 5555
  * 7777

These alerts are emitted alongside YAML based ones and are also counted in metrics. You do not need to write rules for them.

---

## Prometheus metrics

`internal/metrics` exposes two counters via the standard Prometheus registry.

Endpoint:

```text
http://<prom-addr>/metrics
```

Metrics:

* `ebpf_guard_events_total{type="exec|open|connect"}`
  Counter, increments once per raw event received from the ring buffer.

* `ebpf_guard_alerts_total{rule_id="..."}`
  Counter, increments once per alert, including built in ones. The label value is `rule_id` from the engine.

Example scrape:

```text
# HELP ebpf_guard_events_total Number of raw events observed by ebpf-guard, labelled by type.
# TYPE ebpf_guard_events_total counter
ebpf_guard_events_total{type="exec"} 124
ebpf_guard_events_total{type="open"} 560
ebpf_guard_events_total{type="connect"} 32

# HELP ebpf_guard_alerts_total Number of alerts raised by ebpf-guard, labelled by rule id.
# TYPE ebpf_guard_alerts_total counter
ebpf_guard_alerts_total{rule_id="builtin_fileless_exec"} 2
ebpf_guard_alerts_total{rule_id="builtin_crypto_exec"} 1
ebpf_guard_alerts_total{rule_id="suspicious_shell"} 3
```

You can either scrape `ebpf-guard` directly or run it behind a local Prometheus exporter that you already use.

---

## Typical deployment patterns

Some realistic ways to run `ebpf-guard`:

* On a single important server

  * compile once, copy `ebpf-guard` and `ebpf_guard.bpf.o`
  * run under systemd as root
  * scrape metrics with your main Prometheus
  * ship `alerts.jsonl` to a central log store

* On a fleet of nodes with the same kernel

  * build `ebpf_guard.bpf.o` on a compatible build host
  * bake both the binary and the object into an image or AMI
  * manage the service with systemd or your orchestrator
  * allow only metrics and alerts out, no direct access to ring buffer

* Inside a dedicated security node that mirrors traffic

  * less common for syscall based monitoring, but possible if you just want to watch a few hosts from a bastion that can see their processes

There is no cluster manager in this repository. Everything is per host by design.

---

## Tests and development

The test focus is on the detection engine. Tests do not load any BPF programs and do not require root.

From the repo root:

```bash
go test ./...
```

This covers:

* compiling rules from YAML into internal structures
* regexp based matching on `comm` and `filename`
* port bounds logic for connect events
* the fact that `builtin_fileless_exec` fires when expected

Things that are not covered by tests:

* real syscall tracing
* ring buffer behavior under load
* metrics scraping

Those depend on the running kernel and are better validated in a lab.

---

## Limitations

Some important limitations to keep in mind:

* Only Linux is supported.
  There is no plan for other operating systems.

* Only exec, open and connect syscalls are traced.
  There is no visibility into file writes, bind calls, ptrace, etc.
  This is intentional to keep the BPF side simple.

* IPv4 only in the current BPF program.
  `dest_ip` is populated from `struct sockaddr_in`. IPv6 is ignored.

* No container awareness.
  The detector sees processes as the kernel sees them. It does not translate PIDs or namespaces into Kubernetes pod metadata.

* No config reload on the fly.
  Rules are loaded once at process start. To change them, you restart `ebpf-guard`.

* Kernel compatibility is your responsibility.
  If your kernel does not support the used tracepoints or BPF map types, the program will fail to load and you will see explicit errors in the log.

If you need deeper coverage or multi node correlation, you can still treat `ebpf-guard` as a small building block and send its alerts into a larger SIEM or XDR system.

---

## License

The eBPF program declares `SPDX-License-Identifier: GPL-2.0` in the C source file.

There is no top level license file in this repository snapshot.
Before using this code in production or redistributing it, make sure you decide and document the exact licensing for the Go code and how it interacts with the GPL licensed BPF part.
