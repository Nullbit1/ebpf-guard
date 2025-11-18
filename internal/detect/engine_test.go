package detect

import (
    "testing"
    "time"

    "github.com/your-org/ebpf-guard/internal/config"
    "github.com/your-org/ebpf-guard/internal/model"
)

func TestRuleMatchByComm(t *testing.T) {
    cfg := &config.Config{
        Rules: []config.Rule{
            {
                ID:          "shell_rule",
                Description: "shell comm rule",
                EventTypes:  []string{"exec"},
                CommRegex:   "(?i)bash",
            },
        },
    }

    eng, err := NewEngine(cfg)
    if err != nil {
        t.Fatalf("NewEngine: %v", err)
    }

    ev := model.Event{
        Timestamp: time.Now(),
        Pid:       123,
        Tgid:      123,
        Type:      model.EventExec,
        Comm:      "bash",
        Filename:  "/bin/bash",
    }

    alerts := eng.Evaluate(ev)
    found := false
    for _, a := range alerts {
        if a.RuleID == "shell_rule" {
            found = true
            break
        }
    }
    if !found {
        t.Fatalf("expected rule shell_rule to fire, got %+v", alerts)
    }
}

func TestBuiltinFilelessExec(t *testing.T) {
    cfg := &config.Config{}
    eng, err := NewEngine(cfg)
    if err != nil {
        t.Fatalf("NewEngine: %v", err)
    }

    ev := model.Event{
        Timestamp: time.Now(),
        Pid:       1,
        Tgid:      1,
        Type:      model.EventExec,
        Comm:      "weird",
        Filename:  "/dev/shm/.x",
    }

    alerts := eng.Evaluate(ev)
    found := false
    for _, a := range alerts {
        if a.RuleID == "builtin_fileless_exec" {
            found = true
            break
        }
    }
    if !found {
        t.Fatalf("expected builtin_fileless_exec to fire, got %+v", alerts)
    }
}
