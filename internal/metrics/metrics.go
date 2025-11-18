package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/your-org/ebpf-guard/internal/model"
)

var (
    eventsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ebpf_guard_events_total",
            Help: "Number of raw events observed by ebpf-guard, labelled by type.",
        },
        []string{"type"},
    )

    alertsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ebpf_guard_alerts_total",
            Help: "Number of alerts raised by ebpf-guard, labelled by rule id.",
        },
        []string{"rule_id"},
    )
)

func Register(reg *prometheus.Registry) {
    reg.MustRegister(eventsTotal, alertsTotal)
}

func IncEvent(eventType model.EventType) {
    eventsTotal.WithLabelValues(string(eventType)).Inc()
}

func IncAlert(ruleID string) {
    alertsTotal.WithLabelValues(ruleID).Inc()
}
