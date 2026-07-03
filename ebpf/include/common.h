#ifndef __COMMON_H
#define __COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

// CO-RE compatibility macros - these will be overridden when using CO-RE
#define bpf_core_read(dst, sz, src) bpf_probe_read(dst, sz, src)
#define bpf_core_field_exists(T, F) 1
#define bpf_core_field_offset(T, F) offsetof(T, F)
#define bpf_core_field_size(T, F) sizeof(((T *)0)->F)
// Define protocol constants for eBPF
#define IPPROTO_IP 0
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define IPPROTO_IPV6 41

// Define bool type for eBPF if not available
#ifndef __cplusplus
#define bool _Bool
#define true 1
#define false 0
#endif

// DNS header structure
struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
} __attribute__((packed));

// DNS question structure
struct dns_question {
    __u16 qtype;
    __u16 qclass;
} __attribute__((packed));

// DNS resource record structure (simplified)
struct dns_rr {
    __u16 type;
    __u16 class;
    __u32 ttl;
    __u16 rdlength;
} __attribute__((packed));

// IP entry in the whitelist map
struct ip_entry {
    __u64 expires_at;  // Expiration time in monotonic clock nanoseconds
};

// Always allowed networks (localhost and RFC1918)
#define ALLOW_LOCALHOST 1
#define ALLOW_RFC1918 1

// RFC1918 private address ranges
#define RFC1918_10 0x0A000000  // 10.0.0.0/8
#define RFC1918_10_MASK 0xFF000000
#define RFC1918_172 0xAC100000  // 172.16.0.0/12
#define RFC1918_172_MASK 0xFFF00000
#define RFC1918_192 0xC0A80000  // 192.168.0.0/16
#define RFC1918_192_MASK 0xFFFF0000

// Localhost
#define LOCALHOST 0x7F000001  // 127.0.0.1

// Map definitions - use 16 bytes for IPv6, store IPv4 in last 4 bytes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, __u64[2]);    // IP address (16 bytes for IPv6, IPv4 in last 4)
    __type(value, struct ip_entry);  // Expiration timestamp
} ip_whitelist SEC(".maps");

// Map for allowed DNS servers - restrict DNS traffic to only these servers
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, __u64[2]);    // IP address (128-bit)
    __type(value, __u8);     // 1 = allowed DNS server
} allowed_dns_servers SEC(".maps");

// DNS port constant
#define DNS_PORT 53

// Helper: check if IP is in a network
static __always_inline bool is_in_network(__u32 ip, __u32 network, __u32 mask) {
    return (ip & mask) == (network & mask);
}

// IPv6 addresses for always-allowed ranges
// fc00::/7 (Unique Local Addresses - ULA)
#define RFC4193_FC00_HI 0xfc
#define RFC4193_FC00_LO 0x00
// fe80::/10 (Link-local addresses)
#define LINK_LOCAL_FE80 0xfe
#define LINK_LOCAL_MASK 0xc0 // Top 2 bits of second byte should be 10

// Helper: check if IPv4 is always allowed (localhost or RFC1918)
static __always_inline bool is_ipv4_always_allowed(__u32 ip) {
    // Localhost
    if (ip == LOCALHOST || (ip & 0xFF000000) == 0x7F000000) {
        return true;
    }
    
    // RFC1918: 10.0.0.0/8
    if (is_in_network(ip, RFC1918_10, RFC1918_10_MASK)) {
        return true;
    }
    
    // RFC1918: 172.16.0.0/12
    if (is_in_network(ip, RFC1918_172, RFC1918_172_MASK)) {
        return true;
    }
    
    // RFC1918: 192.168.0.0/16
    if (is_in_network(ip, RFC1918_192, RFC1918_192_MASK)) {
        return true;
    }
    
    return false;
}

// Helper: check if IPv6 is always allowed (localhost, ULA, link-local)
static __always_inline bool is_ipv6_always_allowed(__u64 ip_hi, __u64 ip_lo) {
    // Check for localhost (::1)
    if (ip_hi == 0 && ip_lo == 0x0000000000000001) {
        return true;
    }
    
    // Check for Unique Local Addresses (fc00::/7)
    if ((ip_hi >> 56) == RFC4193_FC00_HI && ((ip_hi >> 48) & 0xfe) == RFC4193_FC00_LO) {
        return true;
    }
    
    // Check for link-local (fe80::/10)
    if ((ip_hi >> 56) == LINK_LOCAL_FE80 && ((ip_hi >> 48) & LINK_LOCAL_MASK) == 0x80) {
        return true;
    }
    
    return false;
}

// Helper: check if IP is always allowed (localhost or private ranges)
static __always_inline bool is_always_allowed(__u64 ip_hi, __u64 ip_lo) {
    // Check if it's IPv4-mapped IPv6 (::ffff:0:0/96)
    if (ip_hi == 0 && (ip_lo >> 32) == 0xffff) {
        __u32 ipv4 = (ip_lo & 0xFFFFFFFF);
        return is_ipv4_always_allowed(ipv4);
    }
    
    // Check if it's pure IPv4 (stored in ip_lo with ip_hi = 0)
    if (ip_hi == 0) {
        __u32 ipv4 = (ip_lo & 0xFFFFFFFF);
        // Only check as IPv4 if the upper 32 bits are 0
        if (ip_lo >> 32 == 0) {
            return is_ipv4_always_allowed(ipv4);
        }
    }
    
    // Check IPv6
    return is_ipv6_always_allowed(ip_hi, ip_lo);
}

// Helper: check if IP is allowed (always allowed or in whitelist with valid TTL)
static __always_inline bool is_ip_allowed(__u64 ip_hi, __u64 ip_lo) {
    // Check if always allowed
    if (is_always_allowed(ip_hi, ip_lo)) {
        return true;
    }
    
    // Check whitelist
    __u64 key[2] = {ip_hi, ip_lo};
    struct ip_entry *entry = bpf_map_lookup_elem(&ip_whitelist, &key);
    if (!entry) {
        return false;
    }
    
    // Check expiration
    __u64 now = bpf_ktime_get_ns();
    if (now > entry->expires_at) {
        // Expired - remove and deny
        bpf_map_delete_elem(&ip_whitelist, &key);
        return false;
    }
    
    return true;
}

// Helper: check if IP is an allowed DNS server
static __always_inline bool is_dns_server_allowed(__u64 ip_hi, __u64 ip_lo) {
    __u64 key[2] = {ip_hi, ip_lo};
    __u8 *allowed = bpf_map_lookup_elem(&allowed_dns_servers, &key);
    return allowed != NULL;
}

// Helper: validate DNS traffic - only allow DNS to/from configured DNS servers
// Returns true if DNS traffic is allowed, false if it should be blocked
static __always_inline bool is_dns_traffic_valid(
    __u64 dest_ip_hi, __u64 dest_ip_lo, 
    __u64 src_ip_hi, __u64 src_ip_lo,
    __u16 dest_port, __u16 source_port,
    __u8 protocol
) {
    // Only validate DNS traffic (UDP and TCP on port 53)
    if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP) {
        return true; // Allow non-DNS traffic
    }
    
    // Check if this is DNS traffic (port 53 in either direction)
    bool is_dns = (dest_port == DNS_PORT || source_port == DNS_PORT);
    if (!is_dns) {
        return true; // Not DNS traffic, allow through
    }
    
    // Outbound DNS query: destination port 53, source port != 53
    if (dest_port == DNS_PORT && source_port != DNS_PORT) {
        // This is an outbound DNS query - destination must be allowed DNS server
        return is_dns_server_allowed(dest_ip_hi, dest_ip_lo);
    }
    
    // Inbound DNS response: source port 53, destination port != 53  
    if (source_port == DNS_PORT && dest_port != DNS_PORT) {
        // This is an inbound DNS response - source must be allowed DNS server
        return is_dns_server_allowed(src_ip_hi, src_ip_lo);
    }
    
    // For other DNS traffic patterns (like local DNS server communication), allow it
    return true;
}

#endif // __COMMON_H
