#include "../include/common.h"

char _license[] SEC("license") = "GPL";

// Helper function to skip DNS name (handles compression)
static __always_inline char *skip_dns_name(char *ptr, char *end) {
    if (ptr >= end) return end;
    
    while (1) {
        if (ptr >= end) return end;
        
        unsigned char c = *ptr;
        
        // Check for compression pointer (top 2 bits set)
        if ((c & 0xC0) == 0xC0) {
            // Compressed name - skip the pointer (2 bytes)
            ptr += 2;
            break;
        }
        
        // Check for end of name (zero-length label)
        if (c == 0) {
            ptr += 1; // Skip the zero byte
            break;
        }
        
        // Skip the length byte and the label
        int len = c;
        ptr += 1 + len;
    }
    
    return ptr;
}

// DNS response interceptor - hooks onto UDP traffic on port 53
// This XDP program intercepts DNS responses and extracts A records
// to add them to the whitelist with their TTL

// Section for loading as XDP program
SEC("xdp_dns")
int dns_intercept(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Only handle IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Check packet length
    __u32 ip_len = bpf_ntohs(ip->tot_len);
    if (data + sizeof(*eth) + ip_len > data_end) {
        return XDP_PASS;
    }
    
    // Only handle UDP
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    
    // Parse UDP header
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data + sizeof(*eth) + ip_len) {
        return XDP_PASS;
    }
    
    // Check if this is a DNS response (destination port 53)
    // Note: In XDP, we see packets before they go out or come in
    // For DNS responses coming in, the destination port would be the local port
    // For DNS queries going out, the source port would be the local port
    // We want to intercept responses coming IN to port 53
    if (udp->dest != bpf_htons(53)) {
        // Not a DNS response to port 53
        return XDP_PASS;
    }
    
    // Check if it's a response (QR bit set in DNS flags)
    struct dns_header *dns_hdr = (void *)(udp + 1);
    if ((void *)(dns_hdr + 1) > data + sizeof(*eth) + ip_len) {
        return XDP_PASS;
    }
    
    // Check QR bit (response bit)
    if (!(dns_hdr->flags & 0x8000)) {
        // This is a query, not a response
        return XDP_PASS;
    }
    
    // Check if there are any answers
    __u16 ancount = bpf_ntohs(dns_hdr->ancount);
    if (ancount == 0) {
        // No answers in response
        return XDP_PASS;
    }
    
    // Parse the DNS response to find A records
    // DNS message format:
    // [Header][Questions][Answers][Authority][Additional]
    // We need to skip the header and questions to get to answers
    
    char *ptr = (char *)(dns_hdr + 1);
    char *end = data + sizeof(*eth) + ip_len;
    
    // Skip questions (qdcount * (name + qtype + qclass))
    __u16 qdcount = bpf_ntohs(dns_hdr->qdcount);
    int i;
    for (i = 0; i < qdcount; i++) {
        // Skip name (variable length, compressed format)
        ptr = skip_dns_name(ptr, end);
        if (ptr >= end) {
            return XDP_PASS;
        }
        
        // Skip question type and class (4 bytes)
        ptr += 4;
        if (ptr >= end) {
            return XDP_PASS;
        }
    }
    
    // Now parse answer records
    for (i = 0; i < ancount; i++) {
        if (ptr + 12 > end) { // Minimum RR header size
            break;
        }
        
        // Parse resource record header
        // struct dns_rr *rr = (struct dns_rr *)ptr;
        
        // Skip name (variable length)
        ptr += 2; // Skip the name pointer/offset for now (simplified)
        if (ptr >= end) {
            break;
        }
        
        // Read type and class properly from current position
        __u16 rr_type = bpf_ntohs(*(__u16 *)ptr);
        __u16 rr_class = bpf_ntohs(*(__u16 *)(ptr + 2));
        __u32 ttl = bpf_ntohl(*(__u32 *)(ptr + 4));
        __u16 rdlength = bpf_ntohs(*(__u16 *)(ptr + 8));
        
        // Check if this is an A record (Type = 1) and IN class (Class = 1)
        if (rr_type != 1 || rr_class != 1) { // A record and IN class
            // Skip to next record
            ptr += 10 + rdlength; // Skip the rest of the RR
            continue;
        }
        
        // This is an A record - extract IPv4 address
        if (ptr + 10 + rdlength > end) {
            break;
        }
        
        // IP is at ptr + 10 (after name pointer, type, class, ttl, rdlength)
        char *ip_addr_ptr = ptr + 10;
        __u32 ip_addr;
        
        // Copy 4 bytes of IPv4 address
        bpf_core_read(&ip_addr, sizeof(ip_addr), ip_addr_ptr);
        
        // Apply TTL bounds (clamp to reasonable values)
        // Use minimum of 5 seconds, maximum of 24 hours
        if (ttl < 5) ttl = 5;
        if (ttl > 86400) ttl = 86400; // 24 hours
        
        // Store in whitelist with expiration
        __u64 now = bpf_ktime_get_ns();
        // Convert TTL (seconds) to nanoseconds and add to current time
        __u64 expires_at = now + ((__u64)ttl * 1000000000);
        
        // Convert IPv4 address to 128-bit format
        __u64 ip_key[2] = {0, 0};
        ip_key[1] = (__u64)ip_addr;
        
        struct ip_entry entry = {.expires_at = expires_at};
        bpf_map_update_elem(&ip_whitelist, &ip_key, &entry, BPF_ANY);
        
        // Log the addition (using bpf_printk in newer kernels)
        // bpf_printk("Added IPv4 %u to whitelist, TTL=%u", ip_addr, ttl);
        
        // Move to next record
        ptr += 10 + rdlength;
    }
    
    return XDP_PASS;
}

// Section for IPv6 DNS interception
SEC("xdp_dns_v6")
int dns_intercept_v6(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Only handle IPv6 packets
    if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
        return XDP_PASS;
    }
    
    // Parse IPv6 header
    struct ipv6hdr *ip6 = data + sizeof(*eth);
    if ((void *)(ip6 + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Check packet length from IPv6 payload length
    __u32 ip_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
    if (data + sizeof(*eth) + ip_len > data_end) {
        return XDP_PASS;
    }
    
    // Only handle UDP
    if (ip6->nexthdr != IPPROTO_UDP) {
        return XDP_PASS;
    }
    
    // Parse UDP header
    struct udphdr *udp = data + sizeof(*eth) + sizeof(*ip6);
    if ((void *)(udp + 1) > data + sizeof(*eth) + ip_len) {
        return XDP_PASS;
    }
    
    // Check if this is a DNS response (destination port 53)
    if (udp->dest != bpf_htons(53)) {
        // Not a DNS response to port 53
        return XDP_PASS;
    }
    
    // Check if it's a response (QR bit set in DNS flags)
    struct dns_header *dns_hdr = (void *)(udp + 1);
    if ((void *)(dns_hdr + 1) > data + sizeof(*eth) + ip_len) {
        return XDP_PASS;
    }
    
    // Check QR bit (response bit)
    if (!(dns_hdr->flags & 0x8000)) {
        // This is a query, not a response
        return XDP_PASS;
    }
    
    // Check if there are any answers
    __u16 ancount = bpf_ntohs(dns_hdr->ancount);
    if (ancount == 0) {
        // No answers in response
        return XDP_PASS;
    }
    
    // Parse the DNS response to find A and AAAA records
    char *ptr = (char *)(dns_hdr + 1);
    char *end = data + sizeof(*eth) + ip_len;
    
    // Skip questions (qdcount * (name + qtype + qclass))
    __u16 qdcount = bpf_ntohs(dns_hdr->qdcount);
    int i;
    for (i = 0; i < qdcount; i++) {
        // Skip name (variable length, compressed format)
        ptr = skip_dns_name(ptr, end);
        if (ptr >= end) {
            return XDP_PASS;
        }
        
        // Skip question type and class (4 bytes)
        ptr += 4;
        if (ptr >= end) {
            return XDP_PASS;
        }
    }
    
    // Now parse answer records
    for (i = 0; i < ancount; i++) {
        if (ptr + 12 > end) { // Minimum RR header size
            break;
        }
        
        // Skip name (variable length)
        ptr += 2; // Skip the name pointer/offset for now (simplified)
        if (ptr >= end) {
            break;
        }
        
        // Read type and class properly from current position
        __u16 rr_type = bpf_ntohs(*(__u16 *)ptr);
        __u16 rr_class = bpf_ntohs(*(__u16 *)(ptr + 2));
        __u32 ttl = bpf_ntohl(*(__u32 *)(ptr + 4));
        __u16 rdlength = bpf_ntohs(*(__u16 *)(ptr + 8));
        
        // Check record type
        if (rr_type == 1 && rr_class == 1) { // A record (IPv4)
            // This is an A record - extract IPv4 address
            if (ptr + 10 + rdlength > end) {
                break;
            }
            
            char *ip_addr_ptr = ptr + 10;
            __u32 ip_addr;
            
            // Copy 4 bytes of IPv4 address
            bpf_core_read(&ip_addr, sizeof(ip_addr), ip_addr_ptr);
            
            // Apply TTL bounds
            if (ttl < 5) ttl = 5;
            if (ttl > 86400) ttl = 86400; // 24 hours
            
            // Store in whitelist with expiration
            __u64 now = bpf_ktime_get_ns();
            __u64 expires_at = now + ((__u64)ttl * 1000000000);
            
            // Convert IPv4 address to 128-bit format
            __u64 ip_key[2] = {0, 0};
            ip_key[1] = (__u64)ip_addr;
            
            struct ip_entry entry = {.expires_at = expires_at};
            bpf_map_update_elem(&ip_whitelist, &ip_key, &entry, BPF_ANY);
        
        } else if (rr_type == 28 && rr_class == 1) { // AAAA record (IPv6)
            // This is an AAAA record - extract IPv6 address
            if (ptr + 10 + rdlength > end) {
                break;
            }
            
            char *ip6_addr_ptr = ptr + 10;
            __u64 ip6_hi, ip6_lo;
            
            // Copy 16 bytes of IPv6 address
            bpf_core_read(&ip6_hi, sizeof(ip6_hi), ip6_addr_ptr);
            bpf_core_read(&ip6_lo, sizeof(ip6_lo), ip6_addr_ptr + 8);
            
            // Apply TTL bounds
            if (ttl < 5) ttl = 5;
            if (ttl > 86400) ttl = 86400; // 24 hours
            
            // Store in whitelist with expiration
            __u64 now = bpf_ktime_get_ns();
            __u64 expires_at = now + ((__u64)ttl * 1000000000);
            
            // IPv6 address is already in the right format
            __u64 ip_key[2] = {ip6_hi, ip6_lo};
            
            struct ip_entry entry = {.expires_at = expires_at};
            bpf_map_update_elem(&ip_whitelist, &ip_key, &entry, BPF_ANY);
        }
        
        // Move to next record
        ptr += 10 + rdlength;

    }
    
    return XDP_PASS;
}
