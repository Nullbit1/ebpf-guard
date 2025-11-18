package detect

import (
    "fmt"
    "regexp"
    "strings"
    "time"

    "github.com/your-org/ebpf-guard/internal/config"
    "github.com/your-org/ebpf-guard/internal/model"
)

type Alert struct {
    Timestamp   time.Time       `json:"timestamp"`
    RuleID      string          `json:"rule_id"`
    Description string          `json:"description"`
    EventType   model.EventType `json:"event_type"`
    Event       model.Event     `json:"event"`
}

type compiledRule struct {
    id          string
    description string
    eventTypes  map[model.EventType]struct{}

    commRe     *regexp.Regexp
    filenameRe *regexp.Regexp

    minDestPort *int
    maxDestPort *int
}

type Engine struct {
    rules []*compiledRule
}

func NewEngine(cfg *config.Config) (*Engine, error) {
    var compiled []*compiledRule
    for _, r := range cfg.Rules {
        cr := &compiledRule{
            id:          r.ID,
            description: r.Description,
            eventTypes:  map[model.EventType]struct{}{},
            minDestPort: r.MinDestPort,
            maxDestPort: r.MaxDestPort,
        }
        if cr.id == "" {
            return nil, fmt.Errorf("rule without id")
        }
        if len(r.EventTypes) == 0 {
            return nil, fmt.Errorf("rule %s has no event_types", r.ID)
        }
        for _, et := range r.EventTypes {
            switch strings.ToLower(et) {
            case "exec":
                cr.eventTypes[model.EventExec] = struct{}{}
            case "open":
                cr.eventTypes[model.EventOpen] = struct{}{}
            case "connect":
                cr.eventTypes[model.EventConnect] = struct{}{}
            default:
                return nil, fmt.Errorf("rule %s has unknown event_type %q", r.ID, et)
            }
        }
        if r.CommRegex != "" {
            re, err := regexp.Compile(r.CommRegex)
            if err != nil {
                return nil, fmt.Errorf("rule %s comm_regex: %w", r.ID, err)
            }
            cr.commRe = re
        }
        if r.FilenameRegex != "" {
            re, err := regexp.Compile(r.FilenameRegex)
            if err != nil {
                return nil, fmt.Errorf("rule %s filename_regex: %w", r.ID, err)
            }
            cr.filenameRe = re
        }
        compiled = append(compiled, cr)
    }
    return &Engine{rules: compiled}, nil
}

func (e *Engine) Evaluate(ev model.Event) []Alert {
    var alerts []Alert

    // Built-in heuristics
    alerts = append(alerts, builtinHeuristics(ev)...)

    // Configured rules
    for _, r := range e.rules {
        if _, ok := r.eventTypes[ev.Type]; !ok {
            continue
        }
        if r.commRe != nil && !r.commRe.MatchString(ev.Comm) {
            continue
        }
        if r.filenameRe != nil && !r.filenameRe.MatchString(ev.Filename) {
            continue
        }
        if r.minDestPort != nil && ev.DestPort < uint16(*r.minDestPort) {
            continue
        }
        if r.maxDestPort != nil && ev.DestPort > uint16(*r.maxDestPort) {
            continue
        }

        alerts = append(alerts, Alert{
            Timestamp:   time.Now().UTC(),
            RuleID:      r.id,
            Description: r.description,
            EventType:   ev.Type,
            Event:       ev,
        })
    }

    return alerts
}

func builtinHeuristics(ev model.Event) []Alert {
    var alerts []Alert

    // Fileless exec – exec from memfd, /dev/shm, /proc/self/fd
    if ev.Type == model.EventExec {
        lower := strings.ToLower(ev.Filename)
        if strings.HasPrefix(lower, "/dev/shm/") ||
            strings.HasPrefix(lower, "/tmp/.") ||
            strings.HasPrefix(lower, "/proc/self/fd/") ||
            strings.HasPrefix(lower, "memfd:") {
            alerts = append(alerts, Alert{
                Timestamp:   time.Now().UTC(),
                RuleID:      "builtin_fileless_exec",
                Description: "Fileless or memory-backed executable",
                EventType:   ev.Type,
                Event:       ev,
            })
        }

        // Suspicious shell names
        if looksLikeShell(ev.Comm) || looksLikeShell(ev.Filename) {
            alerts = append(alerts, Alert{
                Timestamp:   time.Now().UTC(),
                RuleID:      "builtin_suspicious_shell",
                Description: "Suspicious shell execution",
                EventType:   ev.Type,
                Event:       ev,
            })
        }

        // Known-ish miner names
        lowerComm := strings.ToLower(ev.Comm)
        lowerFile := strings.ToLower(ev.Filename)
        if strings.Contains(lowerComm, "xmrig") || strings.Contains(lowerFile, "xmrig") ||
            strings.Contains(lowerComm, "minerd") || strings.Contains(lowerFile, "minerd") ||
            strings.Contains(lowerComm, "cpuminer") || strings.Contains(lowerFile, "cpuminer") {
            alerts = append(alerts, Alert{
                Timestamp:   time.Now().UTC(),
                RuleID:      "builtin_crypto_exec",
                Description: "Executable name looks like a crypto miner",
                EventType:   ev.Type,
                Event:       ev,
            })
        }
    }

    if ev.Type == model.EventConnect {
        if ev.DestPort == 3333 || ev.DestPort == 4444 ||
            ev.DestPort == 5555 || ev.DestPort == 7777 {
            alerts = append(alerts, Alert{
                Timestamp:   time.Now().UTC(),
                RuleID:      "builtin_crypto_port",
                Description: "Outgoing connection on common crypto-miner port",
                EventType:   ev.Type,
                Event:       ev,
            })
        }
    }

    return alerts
}

func looksLikeShell(s string) bool {
    s = strings.ToLower(s)
    return strings.Contains(s, "bash") ||
        s == "sh" ||
        strings.Contains(s, "zsh") ||
        strings.Contains(s, "ksh") ||
        strings.Contains(s, "dash")
}
