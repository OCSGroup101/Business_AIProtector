// Copyright 2026 Omni Cyber Solutions LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// BPF program: network_monitor
// Tracepoint: syscalls/sys_enter_connect
// Emits NetworkEvent to NETWORK_EVENTS perf event array.
//
// Only AF_INET (IPv4) connections are captured in this version.
// AF_INET6 support can be added by extending NetworkEvent and checking sa_family.
//
// Build:
//   clang -target bpf -O2 -g \
//         -I /usr/include/$(uname -m)-linux-gnu \
//         -c network_monitor.bpf.c \
//         -o network_monitor.bpf.o

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Shared struct — must match agent/src/collectors/ebpf/network.rs ──────────

struct network_event {
    __u32 pid;
    __u32 uid;
    __u32 dst_ip;    // IPv4 big-endian (network byte order)
    __u16 dst_port;  // big-endian (network byte order)
    __u8  protocol;
    __u8  _pad;
};

// Minimal sockaddr_in definition (avoid pulling in full kernel headers)
struct oc_sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;   // big-endian
    __u32 sin_addr;   // big-endian
    __u8  sin_zero[8];
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} NETWORK_EVENTS SEC(".maps");

// Per-CPU scratch buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct network_event);
} net_heap SEC(".maps");

// ─── Tracepoint context for syscalls/sys_enter_connect ───────────────────────
// Layout from /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format

struct sys_enter_connect_args {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    __s32 __syscall_nr;
    __u64 fd;
    struct sockaddr *uservaddr; // user-space pointer
    __u32 addrlen;
};

// ─── Handler ──────────────────────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct sys_enter_connect_args *ctx)
{
    // Read the sockaddr family from user space first (2-byte peek)
    __u16 sa_family = 0;
    if (bpf_probe_read_user(&sa_family, sizeof(sa_family), ctx->uservaddr) < 0)
        return 0;

    // Only handle AF_INET (2) for now
    if (sa_family != 2 /* AF_INET */)
        return 0;

    __u32 zero = 0;
    struct network_event *evt = bpf_map_lookup_elem(&net_heap, &zero);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(*evt));

    // PID and UID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    evt->pid = (__u32)(pid_tgid >> 32);
    evt->uid = (__u32)(uid_gid & 0xFFFFFFFF);

    // Read the full sockaddr_in from user space
    struct oc_sockaddr_in sin = {};
    if (bpf_probe_read_user(&sin, sizeof(sin), ctx->uservaddr) < 0)
        return 0;

    evt->dst_ip   = sin.sin_addr;   // already big-endian
    evt->dst_port = sin.sin_port;   // already big-endian
    evt->protocol = 6;              // TCP (connect() is always TCP)

    bpf_perf_event_output(ctx, &NETWORK_EVENTS, BPF_F_CURRENT_CPU,
                          evt, sizeof(*evt));
    return 0;
}

char _license[] SEC("license") = "Apache";
