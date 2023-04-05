#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>

#define MAX_ROUTE_ENTRIES 100000
#define MAX_ARP_ENTRIES 10
#define MIN_PACKET_LEN 64
#define ETHENER_TYPE_IP 0x0800
#define ETHENER_TYPE_ETH 0x0806
#define ARP_OP_REQUEST 1
#define ARP_HTYPE_ETHER 1
#define ARP_OP_REPLY 2
#define IP_PROTOCOL 4
#define MAC_LEN 6
#define ICMP_DESTINATION_UNREACHABLE 3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0


/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_entry *mac_table;
int mac_table_len;

/* Queue */
struct queue *q;

/* ARP */
struct arp_header *arp_table;

/* Ethernet header */
struct ether_header *eth_header;


int compare_table(const void *a, const void *b) {
	struct route_table_entry *el1= (struct route_table_entry *)a;
	struct route_table_entry *el2 = (struct route_table_entry *)b;

	if(el1->mask == el2->mask) 
		return el1->prefix - el2->prefix; 
	else 
		return el2->mask - el1->mask;
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *best_route = NULL;
    uint32_t best_mask = 0;
    int left = 0;
    int right = rtable_len - 1;

    while (left <= right) {
        int mid = left + ((right - left) >> 1) / 2;

        if ((rtable[mid].mask & rtable[mid].prefix) == (ip_dest & rtable[mid].mask)) {
            if (rtable[mid].mask > best_mask) {
                best_mask = rtable[mid].mask;
                best_route = &rtable[mid];
            }
	    left = mid + 1;									
        } else if ((rtable[mid].mask & rtable[mid].prefix) < (ip_dest & rtable[mid].mask)) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return best_route;
}

struct arp_entry *get_mac_entry(uint32_t given_ip) {
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == given_ip) {
			return &mac_table[i];
		}
	}

	return NULL;
}


int main(int argc, char *argv[])
{

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);
	DIE(rtable == NULL, "memory");


	mac_table = malloc(sizeof(struct  arp_entry) * MAX_ARP_ENTRIES);
	DIE(mac_table == NULL, "memory");

	rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_table);

	q = queue_create();
	DIE(q == NULL, "queue_create");
	

	while (1) {

		int interface;
		size_t len;
		char* buf = malloc(MAX_PACKET_LEN);

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		if (ntohs(eth_hdr->ether_type) == ETHENER_TYPE_IP) {
			printf("\nIP packet\n");
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			void *payload = buf + sizeof(struct ether_header) + sizeof(struct iphdr);

			if (ip_hdr->version != IP_PROTOCOL) {
				printf("bad version\n");
				continue;
			}

			if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
				printf("Bad checksum\n");
				continue;
			}

			if (ip_hdr->protocol == 1) {
				struct icmphdr *icmph  = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				if (icmph->type == ICMP_ECHO_REQUEST && icmph->code == 0 && ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
					printf("ICMP ECHO REQUEST\n");

					uint32_t temp = ip_hdr->saddr;
					ip_hdr->saddr = ip_hdr->daddr;
					ip_hdr->daddr = temp;

					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
					get_interface_mac(interface, eth_hdr->ether_shost);
					eth_hdr->ether_type = htons(ETHENER_TYPE_IP);

					icmph->type = ICMP_ECHO_REPLY;
					icmph->checksum = 0;
					icmph->checksum = htons(checksum((uint16_t *)icmph, len));

					send_to_link(interface, buf, len);

					continue;
				}
			}

			if (ip_hdr->ttl <= 1) {
				printf("TTL expired\n");
				len += 64;

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
				get_interface_mac(interface, eth_hdr->ether_shost);

				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = inet_addr(get_interface_ip(interface));

				ip_hdr->ttl = 64;
				ip_hdr->check = 0;
				ip_hdr->tot_len += 64;
				ip_hdr->protocol = 1;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				printf("Checksum: %d\n", ip_hdr->check);
				printf("ip_hdr->tot_len: %d\n", ip_hdr->tot_len);

				struct icmphdr *icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr));

				icmph->type = ICMP_TIME_EXCEEDED;
				icmph->code = 0;
				icmph->checksum = 0;
				icmph->un.echo.id = 0;
				icmph->un.echo.sequence = 0;

				char *icmp_payload = (char *)malloc(MAX_PACKET_LEN);
				memcpy(icmp_payload, eth_hdr, sizeof(struct ether_header));
				memcpy(icmp_payload + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
				memcpy(icmp_payload + sizeof(struct ether_header) + sizeof(struct iphdr), icmph, sizeof(struct icmphdr));
				memcpy(icmp_payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), payload, 64);

				printf("icmp_payload: %s\n", icmp_payload);

				icmph->checksum = htons(checksum((uint16_t *)icmph, len));

				memcpy(buf, icmp_payload, len);

				send_to_link(interface, buf, len);
				free(icmph);
				free(icmp_payload);

				continue;
			}

			ip_hdr->ttl--;

			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

			if (best_route == NULL) {
				printf("Best route not found\n");
				len += 64;

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_LEN);
				get_interface_mac(interface, eth_hdr->ether_shost);

				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = inet_addr(get_interface_ip(interface));

				ip_hdr->ttl = 64;
				ip_hdr->check = 0;
				ip_hdr->tot_len += 64;
				ip_hdr->protocol = 1;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				printf("Checksum: %d\n", ip_hdr->check);
				printf("ip_hdr->tot_len: %d\n", ip_hdr->tot_len);

				struct icmphdr *icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr));

				icmph->type = ICMP_DESTINATION_UNREACHABLE;
				icmph->code = 0;
				icmph->checksum = 0;
				icmph->un.echo.id = 0;
				icmph->un.echo.sequence = 0;

				char *icmp_payload = (char *)malloc(MAX_PACKET_LEN);
				memcpy(icmp_payload, eth_hdr, sizeof(struct ether_header));
				memcpy(icmp_payload + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
				memcpy(icmp_payload + sizeof(struct ether_header) + sizeof(struct iphdr), icmph, sizeof(struct icmphdr));
				memcpy(icmp_payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), payload, 64);

				printf("icmp_payload: %s\n", icmp_payload);

				icmph->checksum = htons(checksum((uint16_t *)icmph, len));

				memcpy(buf, icmp_payload, len);

				send_to_link(interface, buf, len);
				free(icmph);
				free(icmp_payload);

				continue;
			}

			
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			interface = best_route->interface;

			struct arp_entry *best_mac = get_mac_entry(best_route->next_hop);
			if (best_mac == NULL) {
				printf("Best mac not found\n");
				printf("Enqueue packet - > ");
				queue_enq(q, buf);
				queue_enq(q, (void *)len);
				queue_enq(q, best_route);
				
				char *buffer = malloc(MAX_PACKET_LEN);

				struct ether_header *eth_header = (struct ether_header *)buffer;
				eth_header->ether_type = htons(ETHENER_TYPE_ETH);
				memset(eth_header->ether_dhost, 0xFF, sizeof(eth_header->ether_dhost));
				get_interface_mac(best_route->interface, eth_header->ether_shost);

				struct arp_header *arp_hdr = (struct arp_header *)(buffer + sizeof(struct ether_header));

				arp_hdr->op = htons(ARP_OP_REQUEST);
				arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
				arp_hdr->tpa = best_route->next_hop;
				arp_hdr->hlen = MAC_LEN;
				arp_hdr->plen = IP_PROTOCOL;
				arp_hdr->htype = htons(ARP_HTYPE_ETHER);
				arp_hdr->ptype = htons(ETHENER_TYPE_IP);
				get_interface_mac(best_route->interface, arp_hdr->sha);
				
			

				send_to_link(best_route->interface, buffer, sizeof(struct ether_header) + sizeof(struct arp_header));
				printf("Sent arp request\n");
				free(buffer);
				continue;
			}

			printf("Sending packet\n");
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			memcpy(&(eth_hdr->ether_dhost), &(get_mac_entry(best_route->next_hop)->mac), sizeof(eth_hdr->ether_dhost));
			send_to_link(best_route->interface, buf, len);
			continue;
		}

		if (ntohs(eth_hdr->ether_type) == ETHENER_TYPE_ETH) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			printf("Got arp packet -->  ");

			if (ntohs(arp_hdr->op) == ARP_OP_REPLY) {
				struct arp_entry *mac_entry = get_mac_entry(arp_hdr->spa);
				printf("Got arp reply   \n");

				if (mac_entry == NULL) {
					mac_table[mac_table_len].ip = arp_hdr->spa;
					memcpy(mac_table[mac_table_len].mac, arp_hdr->sha, sizeof(mac_table[mac_table_len].mac));
					mac_table_len++;
				
					while (queue_empty(q) == 0) {
						printf("Dequeueing\n");
						char *buffer = queue_deq(q);
						size_t len = (size_t)queue_deq(q);
						struct route_table_entry *best_route = queue_deq(q);

						struct arp_entry *best_mac = get_mac_entry(best_route->next_hop);

						if (best_mac == NULL) {
							printf("Best mac not found\n");
							continue;
						}

						struct ether_header *eth_hdr_pair_packet =
										(struct ether_header *) buffer;
						memcpy(eth_hdr_pair_packet->ether_dhost, best_mac->mac, sizeof(eth_header->ether_dhost));
						send_to_link(best_route->interface, buffer, len);
						printf("Sent queued pacekt\n");
					}
				}
				continue;
			}

			if (ntohs(arp_hdr->op) == ARP_OP_REQUEST) {
				printf("Got arp request, sending an arp reply\n");
				arp_hdr->op = htons(ARP_OP_REPLY);

				memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(eth_header->ether_dhost));
				get_interface_mac(interface, arp_hdr->sha);

				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = inet_addr(get_interface_ip(interface));

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_header->ether_dhost));
				get_interface_mac(interface, eth_hdr->ether_shost);

				send_to_link(interface, buf, len);
			}
		}
	}
}