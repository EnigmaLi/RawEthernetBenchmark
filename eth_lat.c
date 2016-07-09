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

#define ETHER_TYPE	0x0800

int main(int argc, char *argv[]) {

	const int BUFF_SIZE = 64;
	int TEST_REPEAT_NUM = 1000;
	int IS_LOCAL_SERVER = 0;
	//uint8_t MY_DEST_MAC[6] = {0xf4, 0x52, 0x14, 0x94, 0x99, 0x61};
	uint8_t MY_DEST_MAC[6] = {0x00, 0x02, 0xc9, 0x4d, 0x45, 0xc8};

	/***************** Send Init *****************/
	int sock_fd_send;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char send_buff[BUFF_SIZE];
	struct ether_header *eh_send = (struct ether_header *) send_buff;
	struct iphdr *iph_send = (struct iphdr *) (send_buff + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char if_name[IFNAMSIZ];
	
	/* Get interface Name and Add*/
	if(strcmp(argv[1], "server") == 0)
		IS_LOCAL_SERVER = 1;
	else if(strcmp(argv[1], "client") == 0)
		IS_LOCAL_SERVER = 1;
	else {
		printf(">>> Wrong Arg!\n");
		return -1;
	}

	if(strlen(argv[2]) != 17) {
		printf(">>> Invalid Mac Address!\n");
		return -1;
	}


	strcpy(if_name, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sock_fd_send = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
	if (ioctl(sock_fd_send, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, if_name, IFNAMSIZ - 1);
	if (ioctl(sock_fd_send, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(send_buff, 0, BUFF_SIZE);

	/* Ethernet header */
	eh_send->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh_send->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh_send->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh_send->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh_send->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh_send->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh_send->ether_dhost[0] = MY_DEST_MAC[0];
	eh_send->ether_dhost[1] = MY_DEST_MAC[1];
	eh_send->ether_dhost[2] = MY_DEST_MAC[2];
	eh_send->ether_dhost[3] = MY_DEST_MAC[3];
	eh_send->ether_dhost[4] = MY_DEST_MAC[4];
	eh_send->ether_dhost[5] = MY_DEST_MAC[5];
	/* Ethertype field */
	eh_send->ether_type = htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);

	/* Packet data */
	send_buff[tx_len] = 0xde;
	send_buff[tx_len + 1] = 0xad;
	send_buff[tx_len + 2] = 0xbe;
	send_buff[tx_len + 3] = 0xef;

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;

	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC[0];
	socket_address.sll_addr[1] = MY_DEST_MAC[1];
	socket_address.sll_addr[2] = MY_DEST_MAC[2];
	socket_address.sll_addr[3] = MY_DEST_MAC[3];
	socket_address.sll_addr[4] = MY_DEST_MAC[4];
	socket_address.sll_addr[5] = MY_DEST_MAC[5];
	/*********************************************/


	/***************** Recv Init *****************/
	char sender[INET6_ADDRSTRLEN];
	int sock_fd_recv, ret, i;
	int sockopt;
	ssize_t num_bytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t recv_buff[BUFF_SIZE];

	/* Header structures */
	struct ether_header *eh_recv = (struct ether_header *) recv_buff;
	struct iphdr *iph_recv = (struct iphdr *) (recv_buff + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (recv_buff + sizeof(struct iphdr) + sizeof(struct ether_header));

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sock_fd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");	
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, if_name, IFNAMSIZ - 1);
	ioctl(sock_fd_recv, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sock_fd_recv, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sock_fd_recv, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sock_fd_recv);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sock_fd_recv, SOL_SOCKET, SO_BINDTODEVICE, if_name, IFNAMSIZ - 1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sock_fd_recv);
		exit(EXIT_FAILURE);
	}
	/*********************************************/


	/***************** Start Test *****************/
	struct timespec ts;

	/* Work as Client */
	if(!IS_LOCAL_SERVER) {
		double time_measure[TEST_REPEAT_NUM];

		for(int i = 0; i < TEST_REPEAT_NUM; i++) {
			clock_gettime(CLOCK_MONOTONIC, &ts);
			uint64_t t1 = ts.tv_nsec;
			if (sendto(sock_fd_send, send_buff, tx_len, 0, (struct sockaddr*)&socket_address,
															sizeof(struct sockaddr_ll)) < 0) {
	    		printf("Send failed\n");
				return -1;
			}
			printf(">>> Sent!\n");
			while(1) {
				num_bytes = recvfrom(sock_fd_recv, recv_buff, BUFF_SIZE, 0, NULL, NULL);
				if (eh_recv->ether_shost[0] == MY_DEST_MAC[0] &&
					eh_recv->ether_shost[1] == MY_DEST_MAC[1] &&
					eh_recv->ether_shost[2] == MY_DEST_MAC[2] &&
					eh_recv->ether_shost[3] == MY_DEST_MAC[3] &&
					eh_recv->ether_shost[4] == MY_DEST_MAC[4] &&
					eh_recv->ether_shost[5] == MY_DEST_MAC[5] &&
					eh_recv->ether_dhost[0] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] &&
					eh_recv->ether_dhost[1] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] &&
					eh_recv->ether_dhost[2] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] &&
					eh_recv->ether_dhost[3] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] &&
					eh_recv->ether_dhost[4] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] &&
					eh_recv->ether_dhost[5] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]) {
					clock_gettime(CLOCK_MONOTONIC, &ts);
					uint64_t t2 = ts.tv_nsec;
					time_measure[i] = ((double)(t2 - t1)) / (1000.0 * 2); /* Convert ns to us */
					printf(">>> Reply Revieved!\n");
				}
				else {
					continue;
				}
			}
		}
	}

	/* Work as Server */
	else {
		printf(">>> Server Started!\n");
		for(int i = 0; i < TEST_REPEAT_NUM; i++) {
			while(1) {
					num_bytes = recvfrom(sock_fd_recv, recv_buff, BUFF_SIZE, 0, NULL, NULL);
					if (eh_recv->ether_shost[0] == MY_DEST_MAC[0] &&
						eh_recv->ether_shost[1] == MY_DEST_MAC[1] &&
						eh_recv->ether_shost[2] == MY_DEST_MAC[2] &&
						eh_recv->ether_shost[3] == MY_DEST_MAC[3] &&
						eh_recv->ether_shost[4] == MY_DEST_MAC[4] &&
						eh_recv->ether_shost[5] == MY_DEST_MAC[5] &&
						eh_recv->ether_dhost[0] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0] &&
						eh_recv->ether_dhost[1] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1] &&
						eh_recv->ether_dhost[2] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2] &&
						eh_recv->ether_dhost[3] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3] &&
						eh_recv->ether_dhost[4] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4] &&
						eh_recv->ether_dhost[5] == ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5]) {
						clock_gettime(CLOCK_MONOTONIC, &ts);
						uint64_t t2 = ts.tv_nsec;
						printf(">>> My Packet!\n");
						printf(">>> data: [0] %X, [1] %X, [2] %X, [3] %X\n", recv_buff[0], recv_buff[1], recv_buff[2], recv_buff[3]);
					}
					else {
						continue;
					}
			}

			if (sendto(sock_fd_send, send_buff, tx_len, 0, (struct sockaddr*)&socket_address,
																sizeof(struct sockaddr_ll)) < 0) {
					printf("Send failed\n");
					return -1;
			}
		}
	}

	close(sock_fd_send);
	close(sock_fd_recv);
	return 0;
}


