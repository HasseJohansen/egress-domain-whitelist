#include "../include/common.h"

char _license[] SEC("license") = "GPL";

// Connection filter - hooks onto socket operations or network output
// to check if destination IPs are allowed

// Option 1: Socket filter (attaches to sockets)
SEC("socket_filter")
int socket_conn_filter(struct __sk_buff *skb) {
    // Try to get destination IP from socket
    // This is more complex - we need to parse the packet
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return SK_PASS;
    }
    
    // Only handle IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // Try IPv6
        if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
            return SK_PASS;
        }
        
        // IPv6 handling
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if ((void *)(ip6 + 1) > data_end) {
            return SK_PASS;
        }
        
        // Extract destination and source IPs (16 bytes each)
        __u64 dest_ip_hi, dest_ip_lo;
        __u64 src_ip_hi = 0, src_ip_lo = 0;
        bpf_core_read(&dest_ip_hi, sizeof(dest_ip_hi), &ip6->daddr.s6_addr[0]);
        bpf_core_read(&dest_ip_lo, sizeof(dest_ip_lo), &ip6->daddr.s6_addr[8]);
        bpf_core_read(&src_ip_hi, sizeof(src_ip_hi), &ip6->saddr.s6_addr[0]);
        bpf_core_read(&src_ip_lo, sizeof(src_ip_lo), &ip6->saddr.s6_addr[8]);
        
        // Validate DNS traffic for IPv6 (both UDP and TCP)
        if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip6);
            if ((void *)(udp + 1) <= data_end) {
                __u16 dest_port = bpf_ntohs(udp->dest);
                __u16 source_port = bpf_ntohs(udp->source);
                if (dest_port == DNS_PORT || source_port == DNS_PORT) {
                    if (is_dns_traffic_valid(dest_ip_hi, dest_ip_lo, src_ip_hi, src_ip_lo, dest_port, source_port, IPPROTO_UDP)) {
                        return SK_PASS;
                    } else {
                        return SK_DROP;
                    }
                }
            }
        } else if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip6);
            if ((void *)(tcp + 1) <= data_end) {
                __u16 dest_port = bpf_ntohs(tcp->dest);
                __u16 source_port = bpf_ntohs(tcp->source);
                if (dest_port == DNS_PORT || source_port == DNS_PORT) {
                    if (is_dns_traffic_valid(dest_ip_hi, dest_ip_lo, src_ip_hi, src_ip_lo, dest_port, source_port, IPPROTO_TCP)) {
                        return SK_PASS;
                    } else {
                        return SK_DROP;
                    }
                }
            }
        }
        
        // Check if IP is allowed
        if (is_ip_allowed(dest_ip_hi, dest_ip_lo)) {
            return SK_PASS;  // Allow
        }
        
        // Drop the packet
        return SK_DROP;
    }
    
    // IPv4 handling
    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        return SK_PASS;
    }
    
    // Extract destination and source IPs (convert to 128-bit format)
    __u64 dest_ip_hi = 0;
    __u64 dest_ip_lo = 0;
    __u64 src_ip_hi = 0;
    __u64 src_ip_lo = 0;
    __u32 ipv4_dest = ip->daddr;
    __u32 ipv4_src = ip->saddr;
    dest_ip_lo = (__u64)ipv4_dest;
    src_ip_lo = (__u64)ipv4_src;
    
    // Validate DNS traffic (both UDP and TCP)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) {
            __u16 dest_port = bpf_ntohs(udp->dest);
            __u16 source_port = bpf_ntohs(udp->source);
            if (dest_port == DNS_PORT || source_port == DNS_PORT) {
                if (is_dns_traffic_valid(dest_ip_hi, dest_ip_lo, src_ip_hi, src_ip_lo, dest_port, source_port, IPPROTO_UDP)) {
                    return SK_PASS;
                } else {
                    return SK_DROP;
                }
            }
        }
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            __u16 dest_port = bpf_ntohs(tcp->dest);
            __u16 source_port = bpf_ntohs(tcp->source);
            if (dest_port == DNS_PORT || source_port == DNS_PORT) {
                if (is_dns_traffic_valid(dest_ip_hi, dest_ip_lo, src_ip_hi, src_ip_lo, dest_port, source_port, IPPROTO_TCP)) {
                    return SK_PASS;
                } else {
                    return SK_DROP;
                }
            }
        }
    }
    
    // Check if IP is allowed
    if (is_ip_allowed(dest_ip_hi, dest_ip_lo)) {
        return SK_PASS;  // Allow
    }
    
    // Drop the packet
    return SK_DROP;
}

// Option 2: XDP filter (attaches to network interface)
// This can catch all outgoing packets
SEC("xdp_filter")
int xdp_conn_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Handle IP packets
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // Parse IP header
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)(ip + 1) > data_end) {
            return XDP_PASS;
        }
        
        // Extract destination and source IPs (convert to 128-bit format)
        __u64 dest_ip_hi = 0;
        __u64 dest_ip_lo = 0;
        __u64 src_ip_hi = 0;
        __u64 src_ip_lo = 0;
        
        __u32 ipv4_dest = ip->daddr;
        __u32 ipv4_src = ip->saddr;
        dest_ip_lo = (__u64)ipv4_dest;
        src_ip_lo = (__u64)ipv4_src;
        
        // Validate DNS traffic - only allow DNS to/from configured DNS servers (both UDP and TCP)
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) <= data_end) {
                __u16 dest_port = bpf_ntohs(udp->dest);
                __u16 source_port = bpf_ntohs(udp->source);
                
                // Check if this is DNS traffic
                if (dest_port == DNS_PORT || source_port == DNS_PORT) {
                    // Validate DNS traffic - if valid, allow through
                    if (is_dns_traffic_valid(dest_ip_hi, dest_ip_lo, src_ip_hi, src_ip_lo, dest_port, source_port, ip->protocol)) {
                        return XDP_PASS; // DNS traffic is valid, allow through
                    } else {
                        return XDP_DROP; // DNS traffic is not valid, block it
                    }
                }
            }
        } else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip + 1);
            if ((void *)(tcp + 1) <= data_end) {
                __u16 dest_port = bpf_ntohs(tcp->dest);
                __u16 source_port = bpf_ntohs(tcp->source);
                
                // Check if this is DNS traffic (TCP DNS)
                if (dest_port == DNS_PORT || source_port == DNS_PORT) {
                    // Validate DNS traffic - if valid, allow through
                    if (is_dns_traffic_valid(dest_ip_hi, dest_ip_lo, src_ip_hi, src_ip_lo, dest_port, source_port, ip->protocol)) {
                        return XDP_PASS; // DNS traffic is valid, allow through
                    } else {
                        return XDP_DROP; // DNS traffic is not valid, block it
                    }
                }
            }
        }
        
        // Check if IP is allowed (for non-DNS traffic)
        if (is_ip_allowed(dest_ip_hi, dest_ip_lo)) {
            return XDP_PASS;  // Allow
        }
        
        // Drop the packet
        return XDP_DROP;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        // IPv6 handling
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if ((void *)(ip6 + 1) > data_end) {
            return XDP_PASS;
        }
        
        // Extract destination and source IPs (16 bytes each)
        __u64 dest_ip_hi, dest_ip_lo;
        __u64 src_ip_hi, src_ip_lo;
        bpf_core_read(&dest_ip_hi, sizeof(dest_ip_hi), &ip6->daddr.s6_addr[0]);
        bpf_core_read(&dest_ip_lo, sizeof(dest_ip_lo), &ip6->daddr.s6_addr[8]);
        bpf_core_read(&src_ip_hi, sizeof(src_ip_hi), &ip6->saddr.s6_addr[0]);
        bpf_core_read(&src_ip_lo, sizeof(src_ip_lo), &ip6->saddr.s6_addr[8]);
        
        // Validate DNS traffic for IPv6 - only allow DNS to/from configured DNS servers (both UDP and TCP)
        if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) <= data_end) {
                __u16 dest_port = bpf_ntohs(udp->dest);
                __u16 source_port = bpf_ntohs(udp->source);
                
                // Check if this is DNS traffic
                if (dest_port == DNS_PORT || source_port == DNS_PORT) {
                    // Validate DNS traffic - if valid, allow through
                    if (is_dns_traffic_valid(dest_ip_hi, dest_ip_lo, src_ip_hi, src_ip_lo, dest_port, source_port, IPPROTO_UDP)) {
                        return XDP_PASS; // DNS traffic is valid, allow through
                    } else {
                        return XDP_DROP; // DNS traffic is not valid, block it
                    }
                }
            }
        } else if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip6 + 1);
            if ((void *)(tcp + 1) <= data_end) {
                __u16 dest_port = bpf_ntohs(tcp->dest);
                __u16 source_port = bpf_ntohs(tcp->source);
                
                // Check if this is DNS traffic (TCP DNS)
                if (dest_port == DNS_PORT || source_port == DNS_PORT) {
                    // Validate DNS traffic - if valid, allow through
                    if (is_dns_traffic_valid(dest_ip_hi, dest_ip_lo, src_ip_hi, src_ip_lo, dest_port, source_port, IPPROTO_TCP)) {
                        return XDP_PASS; // DNS traffic is valid, allow through
                    } else {
                        return XDP_DROP; // DNS traffic is not valid, block it
                    }
                }
            }
        }
        
        // Check if IP is allowed (for non-DNS traffic)
        if (is_ip_allowed(dest_ip_hi, dest_ip_lo)) {
            return XDP_PASS;  // Allow
        }
        
        // Drop the packet
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

// Option 3: Cgroup SKB filter (for cgroup-based filtering)
SEC("cgroup_skb")
int cgroup_conn_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 1; // SK_PASS
    }
    
    // Only handle IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 1; // SK_PASS
    }
    
    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        return 1; // SK_PASS
    }
    
    // Extract destination IP (convert to 128-bit format)
    __u64 dest_ip_hi = 0;
    __u64 dest_ip_lo = 0;
    __u32 ipv4_addr = bpf_ntohl(ip->daddr);
    dest_ip_lo = (__u64)ipv4_addr;
    
    // Check if IP is allowed
    if (is_ip_allowed(dest_ip_hi, dest_ip_lo)) {
        return 1; // Allow
    }
    
    // Drop the packet
    return 0; // DROP
}
