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

// BPF program: process_monitor
// Tracepoint: sched/sched_process_exec
// Emits ProcessEvent to PROCESS_EVENTS perf event array.
//
// Build:
//   clang -target bpf -O2 -g \
//         -I /usr/include/$(uname -m)-linux-gnu \
//         -c process_monitor.bpf.c \
//         -o process_monitor.bpf.o

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Shared struct — must match agent/src/collectors/ebpf/process.rs ─────────

#define TASK_COMM_LEN 16
#define FILENAME_LEN  256

struct process_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];
    char  filename[FILENAME_LEN];
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

// Perf event output ring — user-space reads events from this map.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} PROCESS_EVENTS SEC(".maps");

// Per-CPU scratch buffer to avoid stack overflow (struct is > 256 bytes).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_event);
} heap SEC(".maps");

// ─── Tracepoint context for sched/sched_process_exec ─────────────────────────
// Layout sourced from /sys/kernel/debug/tracing/events/sched/sched_process_exec/format

struct sched_process_exec_args {
    // common header fields (not used directly)
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    // event-specific fields
    __u32 __data_loc_filename; // offset/len encoded
    __s32 pid;
    __s32 old_pid;
};

// ─── Handler ──────────────────────────────────────────────────────────────────

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct sched_process_exec_args *ctx)
{
    __u32 zero = 0;
    struct process_event *evt = bpf_map_lookup_elem(&heap, &zero);
    if (!evt)
        return 0;

    // Zero out the scratch buffer for safety
    __builtin_memset(evt, 0, sizeof(*evt));

    // Current task PID and UID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    evt->pid = (__u32)(pid_tgid >> 32); // TGID == userspace PID
    evt->uid = (__u32)(uid_gid & 0xFFFFFFFF);

    // Parent PID via task_struct (CO-RE)
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt->ppid = (__u32)BPF_CORE_READ(task, real_parent, tgid);

    // Process name (comm)
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    // Executable filename — encoded as __data_loc (offset | (len << 16))
    // The actual string sits at (ctx + offset_bytes).
    __u32 data_loc   = ctx->__data_loc_filename;
    __u16 str_offset = (__u16)(data_loc & 0xFFFF);
    void *filename_ptr = (void *)ctx + str_offset;
    bpf_probe_read_kernel_str(evt->filename, sizeof(evt->filename), filename_ptr);

    // Emit to user-space via perf ring
    bpf_perf_event_output(ctx, &PROCESS_EVENTS, BPF_F_CURRENT_CPU,
                          evt, sizeof(*evt));
    return 0;
}

char _license[] SEC("license") = "Apache";
