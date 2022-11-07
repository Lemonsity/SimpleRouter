#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Get arp cache and cache requests. */
    struct sr_arpreq * head = sr -> cache.requests;
    while (head != NULL) {
        /* Get retieved req. */
        struct sr_arpreq * req = head; /* Handle arpreq can potentially free the pointer */
        uint32_t ip = req -> ip;
        head = head -> next;

        /* Check if the req ip is in arp table. */
        struct sr_arpentry * cached_value = sr_arpcache_lookup(&(sr -> cache), ip);

        /* Did not found match in arp table. */
        if (cached_value == NULL) {
            /* Did not found match in arp table. */
            handle_arpreq(sr, req);
        } else { /* Found match in arp table. */
            int result = forward_ip_packet(sr, req, cached_value);
            if (!result) {
                sr_arpreq_destroy(&(sr -> cache), req);
            } else {
                free(req);
            }
            free(cached_value);
        }
    }
}

int forward_ip_packet(struct sr_instance* sr,
  struct sr_arpreq* arp_request,
  struct sr_arpentry * target) {
    int result = 0;
    /* Get arp req packet. */
    struct sr_packet *packets = arp_request->packets;
    while (packets != NULL) {
        /* Get packet interface. */
        struct sr_if* interface = longest_prefix_match(sr, arp_request->ip);

        /* Get Ethernet header */
        sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packets->buf;
        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packets->buf + sizeof(sr_ethernet_hdr_t));
        /* Add destination and source ethernet address */
        memcpy(ethernet_header->ether_dhost, target->mac, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

        /* Send packet. */
        result = result + sr_send_packet(sr, packets->buf, packets->len, interface->name);
        packets = packets->next;
    }
    return result;
}

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq * req) {
    time_t time_now = time(NULL);
    /* Check if the last time sending this arp req is one second before. */
    if (difftime(time_now, req->sent) >= 1.0) {
        /* Check if this arp req has sent five times. */
        if (req->times_sent >= 5) {
            /* Get arp req packet. */
            struct sr_packet* packet = req->packets;
            while (packet != NULL) {
                /* Sent icmp unreachable to every arp req packets. */
                send_icmp_unreachable_or_timeout(sr, packet->buf, packet->len, packet->iface, 3, 1);
                packet = packet -> next;
            }
            sr_arpreq_destroy(&(sr->cache), req);
        }
        else {
            /* Get packet interface. */
            struct sr_if* interface = longest_prefix_match(sr, req->ip);
            /* Sent arp req. */
            sr_send_arp_request(sr, interface->name, req->ip);
            req->sent = time(NULL);
            req->times_sent++;
        }
    }
}

int sr_send_arp_request(struct sr_instance * sr, 
    char * interface_name, 
    uint32_t target_ip) {
    /* Get packet interface */
    struct sr_if* interface = sr_get_interface(sr, interface_name);

    /* Create Ethernet and ARP packet */
    sr_ethernet_hdr_t* ethernet_header;
    sr_arp_hdr_t* arp_packet = (sr_arp_hdr_t*)malloc(sizeof(sr_arp_hdr_t));
    unsigned int total_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    ethernet_header = (sr_ethernet_hdr_t *)malloc(total_len);

    /* Create ARP value */
    arp_packet->ar_hrd = ntohs(arp_hrd_ethernet);
    arp_packet->ar_pro = ntohs(ethertype_ip);
    arp_packet->ar_hln = ETHER_ADDR_LEN;
    arp_packet->ar_pln = 0x04;
    arp_packet->ar_op = ntohs(arp_op_request);
    memcpy(arp_packet->ar_sha, interface->addr, ETHER_ADDR_LEN);
    arp_packet->ar_sip = interface->ip;
    int i;
    for(i=0;i<ETHER_ADDR_LEN;i++) {
        arp_packet->ar_tha[i] = 0x00;
    }
    arp_packet->ar_tip = target_ip;

    /* Create Ethernet value */
    memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
    for(i=0;i<ETHER_ADDR_LEN;i++) {
        ethernet_header->ether_dhost[i] = 0xff;
    }
    ethernet_header->ether_type = ntohs(ethertype_arp);
    memcpy(((uint8_t*)ethernet_header) + sizeof(sr_ethernet_hdr_t),
    (uint8_t*)arp_packet, sizeof(sr_arp_hdr_t));

    /* Send arp req packet and return the result. */
    int result = sr_send_packet(sr, (uint8_t*)ethernet_header, total_len, interface->name);
    free(arp_packet);
    free(ethernet_header);
    if (result) {
        return 2;
    }
    return 0;
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}
