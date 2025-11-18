package main

import (
    "context"
    "flag"
    "log"
    "net/http"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"

    "github.com/your-org/ebpf-guard/internal/alerts"
    "github.com/your-org/ebpf-guard/internal/collector"
    "github.com/your-org/ebpf-guard/internal/config"
    "github.com/your-org/ebpf-guard/internal/detect"
    "github.com/your-org/ebpf-guard/internal/metrics"
)

func main() {
    var (
        bpfObject  = flag.String("bpf-object", "./internal/bpf/ebpf_guard.bpf.o", "Path to compiled eBPF object file")
        configPath = flag.String("config", "./config/rules.example.yaml", "Path to YAML rules configuration")
        promAddr   = flag.String("prom-addr", ":9100", "Address for Prometheus metrics (e.g. :9100)")
        alertFile  = flag.String("alert-file", "./alerts.jsonl", "Path to JSON lines alert file")
    )
    flag.Parse()

    cfg, err := config.Load(*configPath)
    if err != nil {
        log.Fatalf("load config: %v", err)
    }

    eng, err := detect.NewEngine(cfg)
    if err != nil {
        log.Fatalf("init detect engine: %v", err)
    }

    writer, err := alerts.NewFileWriter(*alertFile)
    if err != nil {
        log.Fatalf("init alerts writer: %v", err)
    }
    defer writer.Close()

    reg := prometheus.NewRegistry()
    metrics.Register(reg)

    mux := http.NewServeMux()
    mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

    go func() {
        log.Printf("Prometheus metrics listening on %s", *promAddr)
        if err := http.ListenAndServe(*promAddr, mux); err != nil {
            log.Fatalf("metrics HTTP server: %v", err)
        }
    }()

    coll := collector.New(*bpfObject)
    ctx, cancel := collector.WithSignalCancel(context.Background())
    defer cancel()

    if err := coll.Run(ctx, eng, writer); err != nil {
        log.Fatalf("collector: %v", err)
    }
}
