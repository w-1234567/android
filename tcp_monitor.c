// tcp_monitor.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/uio.h>
#include <stdint.h>

struct traffic_event {
    __u32 pid;
    __u32 tgid;
    __u64 timestamp;
    char comm[16];
    __u64 size;
    __u8 is_plain;   // 1:可能明文
    char buf[16];    // 前16字节数据
};

// Ringbuf map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// kprobe tcp_sendmsg
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_send, struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id & 0xFFFFFFFF;
    __u32 tgid = id >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 读取函数参数
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    char buf[16] = {};
    struct iovec iov;
    if (bpf_probe_read_user(&iov, sizeof(iov), &msg->msg_iov[0]) == 0) {
        bpf_probe_read_user(buf, sizeof(buf), iov.iov_base);
    }

    // 简单 ASCII 判定
    int printable = 0;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (buf[i] >= 0x20 && buf[i] <= 0x7E)
            printable++;
    }
    __u8 is_plain = (printable * 100 / 16) > 70 ? 1 : 0;
    if (!is_plain) return 0;

    // 提交事件到 ringbuf
    struct traffic_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;

    event->pid = pid;
    event->tgid = tgid;
    event->timestamp = bpf_ktime_get_ns();
    __builtin_memcpy(event->comm, comm, sizeof(comm));
    event->size = size;
    event->is_plain = 1;
    __builtin_memcpy(event->buf, buf, sizeof(buf));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
