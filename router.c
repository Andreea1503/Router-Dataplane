#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <string.h>

#define MAX_ROUTE_ENTRIES 100000
#define MAX_ARP_ENTRIES 10
#define MIN_PACKET_LEN 64
#define ETHENER_TYPE_IP 0x0800
#define ETHENER_TYPE_ARP 0x0806
#define ARP_OP_REQUEST 1
#define ARP_HTYPE_ETHER 1

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


void bubble_sort(struct route_table_entry *rtable, int rtable_len) {
	for (int i = 0; i < rtable_len; i++) {
    for (int j = i + 1; j < rtable_len; j++) {
        if (rtable[i].mask > rtable[j].mask) {
            struct route_table_entry temp = rtable[i];
            rtable[i] = rtable[j];
            rtable[j] = temp;
        }
    }
}
}


struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *best_route = NULL;
	uint32_t best_mask = 0;

	for (int i = 0; i < rtable_len; i++) {
		if ((rtable[i].mask & ip_dest) == (rtable[i].mask & rtable[i].prefix)) {
			if (rtable[i].mask > best_mask) {
				best_mask = rtable[i].mask;
				best_route = &rtable[i];
			}
		}
	}
	return best_route;

    // struct route_table_entry *best_route = NULL;
    // uint32_t best_mask = 0;
    // int left = 0;
    // int right = rtable_len - 1;

	// // FILE *f = fopen("tabela_r1.txt", "w+");
	// // for (int i = 0; i < rtable_len; i++) {
	// // 	fprintf(f, "%d \n", rtable[i].prefix);
	// // }

	// // fclose(f);

    // while (left <= right) {
    //     int mid = left + (right - left) / 2;

    //     if ((rtable[mid].mask & rtable[mid].prefix) == (ip_dest & rtable[mid].mask)) {
    //         if (rtable[mid].mask > best_mask) {
    //             best_mask = rtable[mid].mask;
    //             best_route = &rtable[mid];
	// 			printf("best route: %d %d\n", best_route->prefix, best_route->mask);
    //         }
	//     left = mid + 1;									
    //     } else if (rtable[mid].prefix < ip_dest) {
    //         left = mid + 1;
    //     } else {
    //         right = mid - 1;
    //     }
    // }

    // return best_route;
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
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * MAX_ROUTE_ENTRIES);
	DIE(rtable == NULL, "memory");


	mac_table = malloc(sizeof(struct  arp_entry) * MAX_ARP_ENTRIES);
	DIE(mac_table == NULL, "memory");

	rtable_len = read_rtable(argv[1], rtable);
	mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	q = queue_create();
	DIE(q == NULL, "queue_create");
	

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		if (ntohs(eth_hdr->ether_type) == ETHENER_TYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		if (ip_hdr->version != 4) {
			printf("bad version\n");
			continue;
		}

		if (htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) != 0) {
			printf("Bad checksum\n");
			continue;
		}

		if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
			printf("Packet not for me\n");
			continue;
		}

		if (ip_hdr->ttl <= 1) {
			printf("bad ttl\n");
			continue;
		}

		ip_hdr->ttl--;

		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

		if (best_route == NULL) {
			printf("Best route not found\n");
			continue;
		}

		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		struct arp_entry *best_mac = get_mac_entry(best_route->next_hop);

		if (best_mac == NULL) {
			printf("Best mac not found\n");
			queue_enq(q, buf);
			struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
			DIE(eth_hdr == NULL, "memory");

			eth_hdr->ether_type = htons(ETHENER_TYPE_ARP);
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			memset(eth_hdr->ether_dhost, 0xFF, sizeof(eth_hdr->ether_dhost));

			struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
			DIE(arp_hdr == NULL, "memory");

			arp_hdr->htype = htons(ARP_HTYPE_ETHER);
			arp_hdr->ptype = htons(ETHENER_TYPE_IP);
			arp_hdr->hlen = 6;
			arp_hdr->plen = 4;
			arp_hdr->op = htons(ARP_OP_REQUEST);
			get_interface_mac(best_route->interface, arp_hdr->sha);
			arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
			memset(arp_hdr->tha, 0, sizeof(arp_hdr->tha));
			arp_hdr->tpa = best_route->next_hop;

			char *buffer = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
			memcpy(buffer, eth_hdr, sizeof(struct ether_header));
			memcpy(buffer + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

			send_to_link(best_route->interface, buffer, sizeof(struct ether_header) + sizeof(struct arp_header));
		}

		get_interface_mac(best_route->interface, eth_hdr->ether_shost);

		memcpy(&(eth_hdr->ether_dhost), &(best_mac->mac), sizeof(eth_hdr->ether_dhost)); 
		

		send_to_link(best_route->interface, buf, len);
		}
	}
}