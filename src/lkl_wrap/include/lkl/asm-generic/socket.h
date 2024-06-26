/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LKL__ASM_GENERIC_SOCKET_H
#define __LKL__ASM_GENERIC_SOCKET_H

#include <lkl/linux/posix_types.h>
#include <lkl/asm/sockios.h>

/* For setsockopt(2) */
#define LKL_SOL_SOCKET	1

#define LKL_SO_DEBUG	1
#define LKL_SO_REUSEADDR	2
#define LKL_SO_TYPE		3
#define LKL_SO_ERROR	4
#define LKL_SO_DONTROUTE	5
#define LKL_SO_BROADCAST	6
#define LKL_SO_SNDBUF	7
#define LKL_SO_RCVBUF	8
#define LKL_SO_SNDBUFFORCE	32
#define LKL_SO_RCVBUFFORCE	33
#define LKL_SO_KEEPALIVE	9
#define LKL_SO_OOBINLINE	10
#define LKL_SO_NO_CHECK	11
#define LKL_SO_PRIORITY	12
#define LKL_SO_LINGER	13
#define LKL_SO_BSDCOMPAT	14
#define LKL_SO_REUSEPORT	15
#ifndef LKL_SO_PASSCRED /* powerpc only differs in these */
#define LKL_SO_PASSCRED	16
#define LKL_SO_PEERCRED	17
#define LKL_SO_RCVLOWAT	18
#define LKL_SO_SNDLOWAT	19
#define LKL_SO_RCVTIMEO_OLD	20
#define LKL_SO_SNDTIMEO_OLD	21
#endif

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define LKL_SO_SECURITY_AUTHENTICATION		22
#define LKL_SO_SECURITY_ENCRYPTION_TRANSPORT	23
#define LKL_SO_SECURITY_ENCRYPTION_NETWORK		24

#define LKL_SO_BINDTODEVICE	25

/* Socket filtering */
#define LKL_SO_ATTACH_FILTER	26
#define LKL_SO_DETACH_FILTER	27
#define LKL_SO_GET_FILTER		LKL_SO_ATTACH_FILTER

#define LKL_SO_PEERNAME		28

#define LKL_SO_ACCEPTCONN		30

#define LKL_SO_PEERSEC		31
#define LKL_SO_PASSSEC		34

#define LKL_SO_MARK			36

#define LKL_SO_PROTOCOL		38
#define LKL_SO_DOMAIN		39

#define LKL_SO_RXQ_OVFL             40

#define LKL_SO_WIFI_STATUS		41
#define LKL_SCM_WIFI_STATUS	LKL_SO_WIFI_STATUS
#define LKL_SO_PEEK_OFF		42

/* Instruct lower device to use last 4-bytes of skb data as FCS */
#define LKL_SO_NOFCS		43

#define LKL_SO_LOCK_FILTER		44

#define LKL_SO_SELECT_ERR_QUEUE	45

#define LKL_SO_BUSY_POLL		46

#define LKL_SO_MAX_PACING_RATE	47

#define LKL_SO_BPF_EXTENSIONS	48

#define LKL_SO_INCOMING_CPU		49

#define LKL_SO_ATTACH_BPF		50
#define LKL_SO_DETACH_BPF		LKL_SO_DETACH_FILTER

#define LKL_SO_ATTACH_REUSEPORT_CBPF	51
#define LKL_SO_ATTACH_REUSEPORT_EBPF	52

#define LKL_SO_CNX_ADVICE		53

#define LKL_SCM_TIMESTAMPING_OPT_STATS	54

#define LKL_SO_MEMINFO		55

#define LKL_SO_INCOMING_NAPI_ID	56

#define LKL_SO_COOKIE		57

#define LKL_SCM_TIMESTAMPING_PKTINFO	58

#define LKL_SO_PEERGROUPS		59

#define LKL_SO_ZEROCOPY		60

#define LKL_SO_TXTIME		61
#define LKL_SCM_TXTIME		LKL_SO_TXTIME

#define LKL_SO_BINDTOIFINDEX	62

#define LKL_SO_TIMESTAMP_OLD        29
#define LKL_SO_TIMESTAMPNS_OLD      35
#define LKL_SO_TIMESTAMPING_OLD     37

#define LKL_SO_TIMESTAMP_NEW        63
#define LKL_SO_TIMESTAMPNS_NEW      64
#define LKL_SO_TIMESTAMPING_NEW     65

#define LKL_SO_RCVTIMEO_NEW         66
#define LKL_SO_SNDTIMEO_NEW         67

#define LKL_SO_DETACH_REUSEPORT_BPF 68

#define LKL_SO_PREFER_BUSY_POLL	69
#define LKL_SO_BUSY_POLL_BUDGET	70

#define LKL_SO_NETNS_COOKIE		71

#define LKL_SO_BUF_LOCK		72

#define LKL_SO_RESERVE_MEM		73

#define LKL_SO_TXREHASH		74

#define LKL_SO_RCVMARK		75


#if __LKL__BITS_PER_LONG == 64 || (defined(__x86_64__) && defined(__ILP32__))
/* on 64-bit and x32, avoid the ?: operator */
#define LKL_SO_TIMESTAMP		LKL_SO_TIMESTAMP_OLD
#define LKL_SO_TIMESTAMPNS		LKL_SO_TIMESTAMPNS_OLD
#define LKL_SO_TIMESTAMPING		LKL_SO_TIMESTAMPING_OLD

#define LKL_SO_RCVTIMEO		LKL_SO_RCVTIMEO_OLD
#define LKL_SO_SNDTIMEO		LKL_SO_SNDTIMEO_OLD
#else
#define LKL_SO_TIMESTAMP (sizeof(lkl_time_t) == sizeof(__lkl__kernel_long_t) ? LKL_SO_TIMESTAMP_OLD : LKL_SO_TIMESTAMP_NEW)
#define LKL_SO_TIMESTAMPNS (sizeof(lkl_time_t) == sizeof(__lkl__kernel_long_t) ? LKL_SO_TIMESTAMPNS_OLD : LKL_SO_TIMESTAMPNS_NEW)
#define LKL_SO_TIMESTAMPING (sizeof(lkl_time_t) == sizeof(__lkl__kernel_long_t) ? LKL_SO_TIMESTAMPING_OLD : LKL_SO_TIMESTAMPING_NEW)

#define LKL_SO_RCVTIMEO (sizeof(lkl_time_t) == sizeof(__lkl__kernel_long_t) ? LKL_SO_RCVTIMEO_OLD : LKL_SO_RCVTIMEO_NEW)
#define LKL_SO_SNDTIMEO (sizeof(lkl_time_t) == sizeof(__lkl__kernel_long_t) ? LKL_SO_SNDTIMEO_OLD : LKL_SO_SNDTIMEO_NEW)
#endif

#define LKL_SCM_TIMESTAMP           LKL_SO_TIMESTAMP
#define LKL_SCM_TIMESTAMPNS         LKL_SO_TIMESTAMPNS
#define LKL_SCM_TIMESTAMPING        LKL_SO_TIMESTAMPING


#endif /* __LKL__ASM_GENERIC_SOCKET_H */
