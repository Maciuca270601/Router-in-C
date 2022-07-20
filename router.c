#include "queue.h"
#include "skel.h"

#define ROUTE_TABLE_SIZE 100000
#define ARP_CACHE_SIZE 10000
#define PAYLOAD_SIZE 1600
#define MACSIZE 6

void send_icmp_message(struct ether_header *eth_old, struct iphdr *iph_old, struct icmphdr *icmp_old, int interface,
					   uint8_t type, uint8_t code, int EchoError) {

	packet packet;
	struct ether_header eth_header;
	struct iphdr ip_header;

	// Construim noul header de ethernet
	memcpy(eth_header.ether_shost, eth_old->ether_dhost, MACSIZE);
	memcpy(eth_header.ether_dhost, eth_old->ether_shost, MACSIZE);
	eth_header.ether_type = htons(ETHERTYPE_IP);

	// Construim noul header the IP
	ip_header.tos = iph_old->tos;
	ip_header.ihl = iph_old->ihl;
	ip_header.version = iph_old->version;
	ip_header.tot_len = htons(sizeof(struct icmphdr) + sizeof(struct iphdr));
	ip_header.id = iph_old->id;
	ip_header.protocol = IPPROTO_ICMP;
	ip_header.ttl = 64;
	ip_header.frag_off = iph_old->frag_off;
	ip_header.saddr = iph_old->daddr;
	ip_header.daddr = iph_old->saddr;
	ip_header.check = 0;
	ip_header.check = ip_checksum((uint8_t *)&ip_header, sizeof(struct iphdr));

	// Construim nould header de ICMP
	if(EchoError == 1) {
		//ECHO
		struct icmphdr icmp_header = {
			.type = type,
			.code = code,
			.checksum = 0,
			.un.echo = {
				.id = icmp_old->un.echo.id,
				.sequence = icmp_old->un.echo.sequence,
			}
		};
		//icmp_header.un.echo.id = icmp_old->un.echo.id;
		//icmp_header.un.echo.sequence = icmp_old->un.echo.sequence;
		icmp_header.checksum = icmp_checksum((uint16_t *)&icmp_header, sizeof(icmp_header));
		
		// Adaugam toate headerele la packetul nou creat
		memcpy(packet.payload, &eth_header, sizeof(struct ether_header));
		memcpy(packet.payload + sizeof(struct ether_header), &ip_header, sizeof(struct iphdr));
		memcpy(packet.payload + sizeof(struct ether_header) + sizeof(struct iphdr), &icmp_header, sizeof(struct icmphdr));
		packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
		packet.interface = interface;
		send_packet(&packet);
	} else {
		//ERROR
		struct icmphdr icmp_header;
		icmp_header.type = type;
		icmp_header.code = code;
		icmp_header.checksum = 0;
		icmp_header.checksum = icmp_checksum((uint16_t *)&icmp_header, sizeof(struct icmphdr) + 64);
		
		// Adaugam toate headerele la packetul nou creat
		memcpy(packet.payload, &eth_header, sizeof(struct ether_header));
		memcpy(packet.payload + sizeof(struct ether_header), &ip_header, sizeof(struct iphdr));
		memcpy(packet.payload + sizeof(struct ether_header) + sizeof(struct iphdr), &icmp_header, sizeof(struct icmphdr));
		packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
		packet.interface = interface;
		send_packet(&packet);
	}
}

void send_arp(struct ether_header *eth_h, struct arp_header arp_h, int interface) {
	
	packet packet_reply;
	// Setam restul de campuri din mesaj
	packet_reply.interface = interface;
	packet_reply.len = sizeof(struct ether_header) + sizeof(struct arp_header);

	// Construim PAYLOAD-ul mesajului
	memset(packet_reply.payload, 0, PAYLOAD_SIZE);
	memcpy(packet_reply.payload, eth_h, sizeof(struct ether_header));
	memcpy(packet_reply.payload + sizeof(struct ether_header), &arp_h, sizeof(struct arp_header));

	// Trimitem Reply-ul
	send_packet(&packet_reply);
}

struct arp_entry *get_arp_entry_from_cache(struct arp_entry *arp_cache, int arp_cache_size, unsigned int ip_addr) {
	int found = 0;
	int i;
	for(i = 0; i < arp_cache_size && found == 0; i++) {
		if(arp_cache[i].ip == ip_addr) {
			found = 1;
		}
	}

	if(found == 0) {
		return NULL;
	} else {
		return &arp_cache[i - 1];
	}
}

struct route_table_entry *get_best_route(struct route_table_entry *route_table, int route_table_size, unsigned int ip_dest) {
	// Cautare liniara

	struct route_table_entry matched[20000];
	int matched_size = 0;

	for(int i = 0; i < route_table_size; i++) {
		if((ip_dest & route_table[i].mask) == route_table[i].prefix) {
			matched[matched_size] = route_table[i];
			matched_size++;
		}
	}

	if(matched_size == 0) {
		return NULL;
	}
	
	unsigned int max_mask = matched[0].mask;
	struct route_table_entry *best_route = &(matched[0]);
	
	
	int i = 1;
	while (i < matched_size) {
		if(matched[i].mask > max_mask) {
			best_route = &(matched[i]);
			max_mask = matched[i].mask;
		}
		i++;
	}
	return best_route;
}	


int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);
	
	// Initializam alte campuri
	int arp_index = 0;
	queue packet_queue = queue_create();
	int queue_size = 0;

	// Alocam memorie pentru arp_cache
	struct arp_entry *arp_cache = (struct arp_entry *)malloc(sizeof(struct arp_entry) * ARP_CACHE_SIZE);
	if(arp_cache == NULL) {
		fprintf(stderr, "arp_cache could not be allocated");
	}
	
	// Alocam memorie pentru route_table
	struct route_table_entry *route_table = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * ROUTE_TABLE_SIZE);
	if(route_table == NULL) {
		fprintf(stderr, "route_table could not be allocated");
	}

	// Citim tabela de rutare a ruterului
	int route_table_size;
	route_table_size = read_rtable(argv[1], route_table);
	if(route_table < 0) {
		fprintf(stderr, "read_rtable failed");
	}

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		struct ether_header *eth_header = (struct ether_header *)m.payload;

		// Verificam daca este packet IP
		if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
			
			// Extragem header-ul de IP
			struct iphdr *ip_header = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_header;

			// Extragem header-ul de ICMP doar daca acesta exista
			if(ip_header->protocol == 1) {
				icmp_header = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
			} else {
				icmp_header = NULL;
			}

			// Obtinem adresa IP a noastra(routerului)
			char *buf = get_interface_ip(m.interface);
			struct in_addr router_ip;
			inet_aton(buf, &router_ip);

			// Verificam daca packetul este pentru noi
			if(ip_header->daddr == router_ip.s_addr) {
				
				//Daca s-a ratacit ii dam drop
				if(icmp_header->type != ICMP_ECHO) {
					// Dropam packetul 
					fprintf(stderr, "Packet drop!");
					continue;
				} else  {
					// Trimitem un ECHO_REPLY
					send_icmp_message(eth_header, ip_header, icmp_header, m.interface, ICMP_ECHOREPLY, ICMP_NET_UNREACH, 1);
					fprintf(stderr, "Echo reply message");
					continue;
				}
			}

			// Verificam daca checksumul a fost corupt
			uint16_t to_check = ip_header->check;
			ip_header->check = 0;
			if(to_check != ip_checksum((uint8_t *)ip_header, sizeof(struct iphdr))) {
				// Dropam packetul
				fprintf(stderr, "Packet drop");
				continue;
			}

			// Verificam Time To Live-ul packetului nostru
			if(ip_header->ttl == 1 || ip_header->ttl == 0) {
				// Dropam packetul + mesaj de eroare ICMP TIME EXCEEDED;
				send_icmp_message(eth_header, ip_header, icmp_header, m.interface, ICMP_TIME_EXCEEDED, ICMP_NET_UNREACH, 0);
				fprintf(stderr, "Packet drop");
				continue;
			}

			// Verificam daca exista ruta pentru packetul nostru
			struct route_table_entry *best_route = get_best_route(route_table, route_table_size, ip_header->daddr);

			// Daca  ruta nu exista, generam ICMP DESTINATION UNREACHABLE
			if(best_route == NULL) {
				send_icmp_message(eth_header, ip_header, icmp_header, m.interface, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, 0);
				fprintf(stderr, "Packet drop");
				continue;
			}

			// Trebuie sa verificam daca avem next_hopul salvat in CACHE
			struct arp_entry *arp_entry = get_arp_entry_from_cache(arp_cache, arp_index, best_route->next_hop);

			// Daca gasim ruta in CACHE, trimitem packetul direct 
			if(arp_entry != NULL) {
				m.interface = best_route->interface;
				get_interface_mac(best_route->interface, eth_header->ether_shost);
				memcpy(eth_header->ether_dhost, arp_entry->mac, MACSIZE);
				
				// Scadeam TTL-ul deoarece packetul nostru circula
				ip_header->ttl = ip_header->ttl - 1;
				ip_header->check = 0;
				ip_header->check = ip_checksum((uint8_t *)ip_header, sizeof(struct iphdr));
				send_packet(&m);
			} else {
				
				// Daca nu gasim ruta in CACHE, generam ARP REQUEST
				packet *copy = (packet *)malloc(sizeof(m));
				if(copy == NULL) {
					fprintf(stderr, "Packet memory failed");
				}
				memcpy(copy, &m, sizeof(m));
				queue_enq(packet_queue, copy);
				queue_size++;

				// Obtinem adresa MAC a ruterului pe interfata pe care urmeaza sa se dea REQUEST
				uint8_t *router_mac = (uint8_t *)malloc(MACSIZE * sizeof(uint8_t));
				if(router_mac == NULL) {
					fprintf(stderr, "Router MAC memory failed");
				}
				get_interface_mac(best_route->interface, router_mac);

				// Setam Ethernet Header-ul
				struct ether_header *eth_req = (struct ether_header *)malloc(sizeof(struct ether_header));
				if(eth_req == NULL) {
					fprintf(stderr, "Ethernet Header memory failed");
				}
				memset(eth_req->ether_dhost, 0xff, MACSIZE);
				memcpy(eth_req->ether_shost, router_mac, MACSIZE);
				eth_req->ether_type = htons(ETHERTYPE_ARP);

				// Setam ARP REQUEST Header-ul
				struct arp_header arp_req;
				struct in_addr router_ip;
				char *z = get_interface_ip(best_route->interface);
				inet_aton(z, &router_ip);

				arp_req.hlen = 6;
				arp_req.plen = 4;
				arp_req.op = htons(ARPOP_REQUEST);
				arp_req.ptype = htons(2048);
				arp_req.htype = htons(ARPHRD_ETHER);
				arp_req.tpa = best_route->next_hop;
				arp_req.spa = router_ip.s_addr;
				memcpy(arp_req.sha, router_mac, MACSIZE);
				memset(arp_req.tha, 0xff, MACSIZE);

				send_arp(eth_req, arp_req, best_route->interface);
			}
		}

		// Verificam daca este packet ARP
		if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_header = (struct arp_header *)(m.payload + sizeof(struct ether_header));

			// Verificam daca am primit REQUEST si trimitem REPLY
			if(ntohs(arp_header->op) == ARPOP_REQUEST) {
				char *buff = get_interface_ip(m.interface);
				struct in_addr src_ip;
				inet_aton(buff, &src_ip);

				// Verificam daca REQUEST-UL era pentru noi
				if(arp_header->tpa == src_ip.s_addr) {
					
					// Obtinem adresa MAC a noastra pe interfata pe care a venit packetul
					uint8_t *router_mac = (uint8_t *)malloc(MACSIZE * sizeof(uint8_t));
					if(router_mac == NULL) {
						fprintf(stderr, "Router MAC memory failed");
					}
					get_interface_mac(m.interface, router_mac);
					
					// Refacem noul header de ethernet
					struct ether_header *eth_reply = (struct ether_header *)malloc(sizeof(struct ether_header));
					if(eth_reply == NULL) {
						fprintf(stderr, "Ethernet Reply memory failed");
					}
					memcpy(eth_reply->ether_dhost, eth_header->ether_shost, MACSIZE);
					memcpy(eth_reply->ether_shost, router_mac, MACSIZE);
					eth_reply->ether_type = eth_header->ether_type;

					// Refacem noul header de arp reply
					struct arp_header arp_reply;
					arp_reply.op = htons(ARPOP_REPLY);
					arp_reply.ptype = htons(2048);
					arp_reply.htype = htons(ARPHRD_ETHER);
					arp_reply.plen = 4;
					arp_reply.hlen = 6;
					arp_reply.tpa = arp_header->spa;
					arp_reply.spa = arp_header->tpa;
					memcpy(arp_reply.sha, eth_reply->ether_shost, MACSIZE);
					memcpy(arp_reply.tha, eth_reply->ether_dhost, MACSIZE);

					// Trimitem ARP_REPLY
					send_arp(eth_reply, arp_reply, m.interface);

				} else {
					// Packet-ul trebuie dropat
					fprintf(stderr, "Drop Packet");
					continue;
				}
			}
			// Verificam daca am primit REPLY si trimitem PACKET
			if(ntohs(arp_header->op) == ARPOP_REPLY) {
				
				// Adaugam ip si mac in ARP CACHE
				struct arp_entry new_entry;
				new_entry.ip = arp_header->spa;
				memcpy(new_entry.mac, arp_header->sha, MACSIZE);

				arp_cache[arp_index++] = new_entry;

				packet **holder_packet_array = (packet **)malloc(queue_size * sizeof(packet *));
				if(holder_packet_array == NULL) {
					fprintf(stderr, "Auxiliary structure memory failed");
				}

				int new_queue_size = 0;
				int counter = 0;
				// Parcurgem coada de packete initiala
				while(counter < queue_size) {

					packet *buffer = (packet *)queue_deq(packet_queue);
					packet extracted_packet = *buffer;
					
					struct iphdr *extracted_ip_header = (struct iphdr *)(extracted_packet.payload + sizeof(struct ether_header));

					// Verificam daca fiecare packet are next_hopul, ip-ul destinatie primit in reply
					struct route_table_entry *rte = get_best_route(route_table, route_table_size, extracted_ip_header->daddr);

					// Trimitem packetul
					if(rte->next_hop == arp_header->spa) {
						extracted_packet.interface = rte->interface;

						// Modific MAC-urile packetului pentru urmatoarea plimbare
						struct ether_header *extracted_eth_header = (struct ether_header *)extracted_packet.payload;
						memcpy(extracted_eth_header->ether_dhost, arp_header->sha, MACSIZE);
						get_interface_mac(rte->interface, extracted_eth_header->ether_shost);
						
						// Modific ttl pentru ca packetul se plimba in continuare
						// Trebuie reverificat check_sumul
						extracted_ip_header->ttl = extracted_ip_header->ttl - 1;
						extracted_ip_header->check = 0;
						extracted_ip_header->check = ip_checksum((uint8_t *)extracted_ip_header, sizeof(struct iphdr));
						
						// Trimitem packetul daca totul a fost OK
						send_packet(&extracted_packet);
					
					} else {
						// Adaugam packetul in structura auxiliara
						holder_packet_array[new_queue_size] = &extracted_packet;
						new_queue_size++;
					}
					counter++;
				}

				// Refacem coada initiala
				counter = 0;
				while(counter < new_queue_size) {
					packet *p = holder_packet_array[counter];
					queue_enq(packet_queue, p);
					counter++;
				}
				queue_size = new_queue_size;
				//Free the auxiliary structure
				free(holder_packet_array);
				//continue;
			}
		}
	}
	return 0;
}
