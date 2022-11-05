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
    struct sr_arpcache cache = sr -> cache;
    struct sr_arpreq * head = sr -> cache.requests;
    while (head != NULL) {
        /* Get retieved req. */
        struct sr_arpreq * req = head; /* Handle arpreq can potentially free the pointer */
        uint32_t ip = req -> ip;
        head = head -> next;

        /* Check if the req ip is in arp table. */
        struct sr_arpentry * cached_value = sr_arpcache_lookup(&cache, ip);

        /* Did not found match in arp table. */
        if (cached_value == NULL) {
            /* Did not found match in arp table. */
            handle_arpreq(sr, req);
        } else { /* Found match in arp table. */
            int result = forward_ip_packet(sr, req, cached_value);
            if (!result) {
              sr_arpreq_destroy(&(cache), req);
            }
            free(req);
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
        struct sr_if* interface = sr_get_interface(sr, packets->iface);

        /* Get Ethernet header */
        sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packets->buf;
        /* Add destination and source ethernet address */
        memcpy(ethernet_header->ether_dhost, target->mac, ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);

        /* Get IP header */
        sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packets->buf + sizeof(sr_ethernet_hdr_t));
        /* Update TTL and check sum */
        ip_header->ip_ttl--;
        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

        /* Send packet. */
        result = result + sr_send_packet(sr, packets->buf, packets->len, packets->iface);
        struct sr_packet *temp = packets;
        packets = packets->next;
        free(temp);
    }
    return result;
}

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq * req) {
    time_t time_now = time(NULL);
    if (difftime(time_now, req -> sent) > 1.0) {
        if (req -> times_sent >= 5) {
            struct sr_packet* packet = req->packets;
            while (packet != NULL) {
                send_icmp_unreachable_or_timeout(sr, packet->buf, packet->len, packet->iface, 3, 1);
                packet = packet -> next;
            }
            sr_arpreq_destroy(&(sr->cache), req);
        }
        else {
            /* TODO send arp request*/
            struct sr_if* interface = sr->if_list;
            while (interface != NULL) {
                sr_send_arp_request(sr, interface->name, req->ip);
                interface = interface -> next;
            }
            req->sent = time(NULL);
            req->times_sent++;
        }
    }
}

int sr_send_arp_request(struct sr_instance * sr, 
    char * interface_name, 
    uint32_t target_ip) {

    uint8_t * combined_packet = (uint8_t *)calloc(1, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)combined_packet;
    sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *)(combined_packet + sizeof(sr_ethernet_hdr_t));

    struct sr_if* interface = sr_get_interface(sr, interface_name);
    int i = 0;
    for (; i < 6; i++) {
        ethernet_header->ether_dhost[i] = 0xff;
    }
    memcpy(ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
    ethernet_header->ether_type = htons(ethertype_arp);

    arp_header->ar_hrd = htons(arp_hrd_ethernet);
    arp_header->ar_pro = htons(0x0800);
    arp_header->ar_hln = 0x06;
    arp_header->ar_pln = 0x04;
    arp_header->ar_op = htons(arp_op_request);
    memcpy(arp_header->ar_sha, interface->addr, ETHER_ADDR_LEN);
    arp_header->ar_sip = htonl(interface->ip);
    /* arp_header->ar_tha: requesting, does not need to fill */
    arp_header->ar_tip = htonl(target_ip);
    
    int result;
    if (result = sr_send_packet(sr, combined_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface_name)) {
        /* TODO handle fail to send error*/
        return result;
    }
    free(combined_packet);
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
