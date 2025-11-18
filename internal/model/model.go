package model

import "time"

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

    Comm     string `json:"comm"`
    Filename string `json:"filename"`

    DestIP   string `json:"dest_ip,omitempty"`
    DestPort uint16 `json:"dest_port,omitempty"`
}
