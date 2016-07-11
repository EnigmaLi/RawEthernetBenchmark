/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include <time.h>

#define DEFAULT_IF	"eth1"

/* ETHER_TALK */
#define ETHER_TYPE	0x809B

#define BUFF_SIZE 64



typedef struct eth_send {
	struct ether_header *eh;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_addr;
	int sock;
	char if_name[IFNAMSIZ];
	uint8_t buff[BUFF_SIZE];
} eth_send;

typedef struct eth_recv {
	struct ether_header *eh;
	int sock;
	int sockopt;
	char if_name[IFNAMSIZ];
	uint8_t buff[BUFF_SIZE];
} eth_recv;

int send_init(eth_send *eth, uint8_t dest_mac[6]) {
	eth->eh = (struct ether_header *) (eth->buff);
	strcpy(eth->if_name, DEFAULT_IF);
	
	/* Open RAW socket to send on */
	if ((eth->sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	    return -1;
	}
	
	/* Get the index of the interface to send on */
	memset(&(eth->if_idx), 0, sizeof(struct ifreq));
	strncpy(eth->if_idx.ifr_name, eth->if_name, IFNAMSIZ - 1);
	if (ioctl(eth->sock, SIOCGIFINDEX, &(eth->if_idx)) < 0) {
	    perror("SIOCGIFINDEX");
	    return -1;
	}
	/* Get the MAC address of the interface to send on */
	memset(&(eth->if_mac), 0, sizeof(struct ifreq));
	strncpy(eth->if_mac.ifr_name, eth->if_name, IFNAMSIZ - 1);
	if (ioctl(eth->sock, SIOCGIFHWADDR, &(eth->if_mac)) < 0) {
	    perror("SIOCGIFHWADDR");
	    return -1;
	}
	
	/* Construct the Ethernet header */
	memset(eth->buff, 0, BUFF_SIZE);
	
	/* Ethernet header */
	(eth->eh)->ether_shost[0] = ((uint8_t *)&((eth->if_mac).ifr_hwaddr.sa_data))[0];
	(eth->eh)->ether_shost[1] = ((uint8_t *)&((eth->if_mac).ifr_hwaddr.sa_data))[1];
	(eth->eh)->ether_shost[2] = ((uint8_t *)&((eth->if_mac).ifr_hwaddr.sa_data))[2];
	(eth->eh)->ether_shost[3] = ((uint8_t *)&((eth->if_mac).ifr_hwaddr.sa_data))[3];
	(eth->eh)->ether_shost[4] = ((uint8_t *)&((eth->if_mac).ifr_hwaddr.sa_data))[4];
	(eth->eh)->ether_shost[5] = ((uint8_t *)&((eth->if_mac).ifr_hwaddr.sa_data))[5];
	(eth->eh)->ether_dhost[0] = dest_mac[0];
	(eth->eh)->ether_dhost[1] = dest_mac[1];
	(eth->eh)->ether_dhost[2] = dest_mac[2];
	(eth->eh)->ether_dhost[3] = dest_mac[3];
	(eth->eh)->ether_dhost[4] = dest_mac[4];
	(eth->eh)->ether_dhost[5] = dest_mac[5];

	/* Ethertype field */
	(eth->eh)->ether_type = htons(ETHER_TYPE);
	
	/* Index of the network device */
	(eth->socket_addr).sll_ifindex = (eth->if_idx).ifr_ifindex;
	(eth->socket_addr).sll_family = AF_PACKET;

	/* Address length*/
	(eth->socket_addr).sll_halen = ETH_ALEN;

	/* Destination MAC */
	(eth->socket_addr).sll_addr[0] = dest_mac[0];
	(eth->socket_addr).sll_addr[1] = dest_mac[1];
	(eth->socket_addr).sll_addr[2] = dest_mac[2];
	(eth->socket_addr).sll_addr[3] = dest_mac[3];
	(eth->socket_addr).sll_addr[4] = dest_mac[4];
	(eth->socket_addr).sll_addr[5] = dest_mac[5];
	
	return 0;
}

int recv_init(eth_recv *eth) {
	eth->eh = (struct ether_header *) (eth->buff);
	strcpy(eth->if_name, DEFAULT_IF);
	
	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((eth->sock = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");
		return -1;
	}
	
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(eth->sock, SOL_SOCKET, SO_REUSEADDR, &(eth->sockopt), sizeof(eth->sockopt)) == -1) {
		perror("setsockopt");
		close(eth->sock);
		return -1;
	}
	/* Bind to device */
	if (setsockopt(eth->sock, SOL_SOCKET, SO_BINDTODEVICE, eth->if_name, IFNAMSIZ - 1) == -1) {
		perror("SO_BINDTODEVICE");
		close(eth->sock);
		return -1;
	}
	
	return 0;
}

int get_char_val(char c) {
	switch(c) {
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		
		case 'a': return 10;
		case 'b': return 11;
		case 'c': return 12;
		case 'd': return 13;
		case 'e': return 14;
		case 'f': return 15;
		
		case 'A': return 10;
		case 'B': return 11;
		case 'C': return 12;
		case 'D': return 13;
		case 'E': return 14;
		case 'F': return 15;
		
		default: return -1;
	}
	return 0;
}

int str_to_mac(char *s, uint8_t *mac) {
	if(strlen(s) != 17)
		return -1;
	for(uint8_t i = 0; i < 6; i++) {
		uint8_t val_h, val_l;
		val_h = get_char_val(s[3 * i]);
		val_l = get_char_val(s[(3 * i) + 1]);
		if((val_h < 0) || (val_l < 0))
			return -1;
		mac[i] = val_h * 16 + val_l;	
	}
	return 0;
}


int main(int argc, char *argv[]) {

	int TEST_REPEAT_NUM = 1000;
	int IS_LOCAL_SERVER = 0;
	uint8_t dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	
	if(strcmp(argv[1], "server") == 0)
		IS_LOCAL_SERVER = 1;
	else if(strcmp(argv[1], "client") == 0)
		IS_LOCAL_SERVER = 0;
	else {
		printf(">>> Invalid Server or Client Option!\n");
		exit(-1);
	}
	
	if(str_to_mac(argv[2], dest_mac) < 0) {
		printf(">>> Invalid Mac Address!\n");
		exit(-1);
	}

	
	eth_send es;
	eth_recv er;
	send_init(&es, dest_mac);
	recv_init(&er);
	
	/***************** Start Test *****************/
	struct timespec ts;

	/* Work as Client */
	if(!IS_LOCAL_SERVER) {
		printf(">>> Client Start Send!\n");
		double time_measure[TEST_REPEAT_NUM];

		for(int i = 0; i < TEST_REPEAT_NUM; i++) {
			clock_gettime(CLOCK_MONOTONIC, &ts);
			uint64_t t1 = ts.tv_nsec;
			//Send
			if (sendto(es.sock, es.buff, BUFF_SIZE, 0, (struct sockaddr*)&(es.socket_addr),
															sizeof(struct sockaddr_ll)) < 0) {
	    		printf("Send failed\n");
				return -1;
			}
			//Recv
			int num_bytes = recvfrom(er.sock, er.buff, BUFF_SIZE, 0, NULL, NULL);
			clock_gettime(CLOCK_MONOTONIC, &ts);
			uint64_t t2 = ts.tv_nsec;
			
			uint64_t nt1, nt2;
			memcpy(&nt1, &er.buff[BUFF_SIZE - 16], sizeof(uint64_t));
			memcpy(&nt1, &er.buff[BUFF_SIZE - 8], sizeof(uint64_t));
			time_measure[i] = (double)((t2 - t1 - (nt2 - nt1)) / (1000.0 * 2));
			printf("%d\n", (t2 - t1));
		}
		double sum = 0.0;
		for(int i = 0; i < TEST_REPEAT_NUM; i++)
			sum += time_measure[i];
		printf(">>> Mean <1000 x 64Bytes> frame: %f us.\n", (sum / 1000));
	}

	/* Work as Server */
	else {
		printf(">>> Server Started!\n");

		for(int i = 0; i < TEST_REPEAT_NUM; i++) {
			//Recv
			int num_bytes = recvfrom(er.sock, er.buff, BUFF_SIZE, 0, NULL, NULL);
			clock_gettime(CLOCK_MONOTONIC, &ts);
			memcpy(&es.buff[BUFF_SIZE - 16], &(ts.tv_nsec), sizeof(uint64_t));
			printf(">>> Receive Data Frame [%d]:\nData:", i);
			for(int i = 0; i < num_bytes; i++)
				printf("%X ", er.buff[i]);
			printf("\n");
			
			//Send
			clock_gettime(CLOCK_MONOTONIC, &ts);
			memcpy(&es.buff[BUFF_SIZE - 8], &(ts.tv_nsec), sizeof(uint64_t));
			if (sendto(es.sock, es.buff, BUFF_SIZE, 0, (struct sockaddr*)&(es.socket_addr),
															sizeof(struct sockaddr_ll)) < 0) {
	    		printf("Send failed\n");
				return -1;
			}
		}
	}
	
	close(es.sock);
	close(er.sock);
	
	return 0;
}
