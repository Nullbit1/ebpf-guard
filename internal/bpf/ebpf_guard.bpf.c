// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    long  id;
    unsigned long args[6];
};

enum event_type {
    EVENT_EXEC = 0,
    EVENT_OPEN = 1,
    EVENT_CONNECT = 2,
};

struct event_t {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u32 event_type;
    __u16 dest_port;
    __u16 _pad;
    __u32 dest_ip4; // network byte order

    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void fill_common(struct event_t *e)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid;
    e->tgid = pid_tgid >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_exec(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[0];

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_EXEC;

    if (filename)
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_OPEN;

    if (filename)
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    const struct sockaddr *uservaddr = (const struct sockaddr *)ctx->args[1];

    struct sockaddr_in sin = {};
    if (!uservaddr)
        return 0;

    if (bpf_probe_read_user(&sin, sizeof(sin), uservaddr) != 0)
        return 0;

    if (sin.sin_family != AF_INET)
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e);
    e->event_type = EVENT_CONNECT;
    e->dest_ip4 = sin.sin_addr.s_addr;
    e->dest_port = sin.sin_port; // network byte order

    const char tag[] = "connect";
    __builtin_memcpy(&e->filename, tag, sizeof(tag));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
