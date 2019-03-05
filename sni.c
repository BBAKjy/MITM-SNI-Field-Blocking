#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netdb.h>
#include <string.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <time.h>

unsigned short ip_checksum(int ip_length, unsigned char buff[]);
unsigned short tcp_checksum(unsigned short *ptr, int nbytes);
void Set_RST_Packet(unsigned char sni_buffer[], unsigned char rst_packet[]);

typedef struct ETHERNET_HEADER
{
	unsigned char dst[6];
	unsigned char src[6];
	unsigned short type;
}ethernet_header;

typedef struct IP_HEADER {
	unsigned char version;
	unsigned char dsf;
	unsigned short total_len;
	unsigned short ident;
	unsigned short fragfo;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char src[4];
	unsigned char dest[4];
}ip_header;

typedef struct TCP_HEADER {
	unsigned short src_port;
	unsigned char dest_port[2];
	unsigned char seq_num[4];
	unsigned char ack_num[4];
	unsigned short flag;
	unsigned short window_size;
	unsigned short checksum;
	unsigned short urgent;

}tcp_header;

typedef struct PSEUDO_HEADER {
	unsigned char src_addr[4];
	unsigned char dest_addr[4];
	unsigned char useless;
	unsigned char protocol;
	unsigned short length;
}pseudo_header;


int main(void) {

	unsigned char sni_buffer[1024];
	memset(sni_buffer, 0, 1024);
	unsigned char buffer[1024];
	memset(buffer, 0, 1024);
	unsigned char rst_packet[1024];

	int socket1;
	socket1 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	int session_length;
	int cipher_length;
	int server_length;



	struct ifreq if_idx;
	struct sockaddr_ll socket_addr;
	memset(&socket_addr, 0, sizeof(struct sockaddr_ll));
	strncpy(if_idx.ifr_ifrn.ifrn_name, "eth0", IFNAMSIZ);
	ioctl(socket1, SIOCGIFINDEX, &if_idx);
	socket_addr.sll_family = PF_PACKET;
	socket_addr.sll_ifindex = if_idx.ifr_ifru.ifru_ivalue;

	int client_len = sizeof(socket_addr);

	unsigned char target_ip[4];
	printf("Target IP : ");
	scanf("%d.%d.%d.%d", &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3]);

	while (1) {

		recvfrom(socket1, sni_buffer, 1024, 0, NULL, &client_len);


		if (target_ip[0] == sni_buffer[26] && target_ip[1] == sni_buffer[27] && target_ip[2] == sni_buffer[28] && target_ip[3] == sni_buffer[29] && sni_buffer[59] == 0x01 && sni_buffer[54] == 0x16 && sni_buffer[23] == 0x06 && sni_buffer[47] == 0x18) {
			session_length = (int)sni_buffer[97];
			cipher_length = (int)sni_buffer[97 + session_length + 2];
			server_length = (int)sni_buffer[97 + session_length + 2 + cipher_length + 13];


			for (int i = 97 + session_length + 2 + cipher_length + 14; i < 97 + session_length + 2 + cipher_length + 14 + server_length; i++) {
				buffer[i - (97 + session_length + 2 + cipher_length + 14)] = sni_buffer[i];

			}
			printf("%s\n", buffer);

			if (strcmp(buffer, "l.www.naver.com") == 0 || strcmp(buffer, "www.naver.com") == 0) {
				Set_RST_Packet(sni_buffer, rst_packet);
				sendto(socket1, rst_packet, 54, 0, (struct sockaddr *)&socket_addr, sizeof(socket_addr));

			}

			memset(sni_buffer, 0, 1024);
			memset(buffer, 0, 1024);

		}

	}

	close(socket1);
}

void Set_RST_Packet(unsigned char sni_buffer[], unsigned char rst_packet[]) {

	unsigned char tcp_checkbuffer[1024];
	memset(tcp_checkbuffer, 0, 1000);
	pseudo_header * pseudohdr = NULL;
	ethernet_header * ethdr = NULL;
	ip_header * iphdr = NULL;
	tcp_header * tcphdr = NULL;
	tcp_header * tcpchk = NULL;

	ethdr = (ethernet_header *)rst_packet;

	ethdr->dst[0] = sni_buffer[6];
	ethdr->dst[1] = sni_buffer[7];
	ethdr->dst[2] = sni_buffer[8];
	ethdr->dst[3] = sni_buffer[9];
	ethdr->dst[4] = sni_buffer[10];
	ethdr->dst[5] = sni_buffer[11];

	ethdr->src[0] = sni_buffer[0];
	ethdr->src[1] = sni_buffer[1];
	ethdr->src[2] = sni_buffer[2];
	ethdr->src[3] = sni_buffer[3];
	ethdr->src[4] = sni_buffer[4];
	ethdr->src[5] = sni_buffer[5];

	ethdr->type = 0x0008;

	iphdr = (ip_header *)&rst_packet[sizeof(ethernet_header)];

	iphdr->version = 0x45;
	iphdr->dsf = 0x00;
	iphdr->total_len = htons(40);
	iphdr->ident = getpid();
	iphdr->fragfo = 0x0000;
	iphdr->ttl = 0x80;
	iphdr->protocol = 0x06;
	iphdr->checksum = 0;

	iphdr->src[0] = sni_buffer[30];
	iphdr->src[1] = sni_buffer[31];
	iphdr->src[2] = sni_buffer[32];
	iphdr->src[3] = sni_buffer[33];

	iphdr->dest[0] = sni_buffer[26];
	iphdr->dest[1] = sni_buffer[27];
	iphdr->dest[2] = sni_buffer[28];
	iphdr->dest[3] = sni_buffer[29];

	iphdr->checksum = htons(ip_checksum(20, rst_packet));

	tcphdr = (tcp_header *)&rst_packet[sizeof(ethernet_header) + sizeof(ip_header)];

	tcphdr->src_port = 0xbb01;
	tcphdr->dest_port[0] = sni_buffer[34];
	tcphdr->dest_port[1] = sni_buffer[35];
	tcphdr->seq_num[0] = sni_buffer[42];
	tcphdr->seq_num[1] = sni_buffer[43];
	tcphdr->seq_num[2] = sni_buffer[44];
	tcphdr->seq_num[3] = sni_buffer[45];
	tcphdr->ack_num[0] = sni_buffer[38];
	tcphdr->ack_num[1] = sni_buffer[39];
	tcphdr->ack_num[2] = sni_buffer[40];
	tcphdr->ack_num[3] = sni_buffer[41] + 1;
	tcphdr->flag = 0x1450;
	tcphdr->window_size = 0xf0fa;
	tcphdr->checksum = 0;
	tcphdr->urgent = 0;


	pseudohdr = (pseudo_header *)&tcp_checkbuffer;

	pseudohdr->src_addr[0] = iphdr->src[0];
	pseudohdr->src_addr[1] = iphdr->src[1];
	pseudohdr->src_addr[2] = iphdr->src[2];
	pseudohdr->src_addr[3] = iphdr->src[3];

	pseudohdr->dest_addr[0] = iphdr->dest[0];
	pseudohdr->dest_addr[1] = iphdr->dest[1];
	pseudohdr->dest_addr[2] = iphdr->dest[2];
	pseudohdr->dest_addr[3] = iphdr->dest[3];

	pseudohdr->useless = 0x00;

	pseudohdr->protocol = iphdr->protocol;

	pseudohdr->length = htons(20);

	tcpchk = (tcp_header *)&tcp_checkbuffer[sizeof(pseudo_header)];

	tcpchk->src_port = tcphdr->src_port;
	tcpchk->dest_port[0] = tcphdr->dest_port[0];
	tcpchk->dest_port[1] = tcphdr->dest_port[1];
	tcpchk->seq_num[0] = tcphdr->seq_num[0];
	tcpchk->seq_num[1] = tcphdr->seq_num[1];
	tcpchk->seq_num[2] = tcphdr->seq_num[2];
	tcpchk->seq_num[3] = tcphdr->seq_num[3];

	tcpchk->ack_num[0] = tcphdr->ack_num[0];
	tcpchk->ack_num[1] = tcphdr->ack_num[1];
	tcpchk->ack_num[2] = tcphdr->ack_num[2];
	tcpchk->ack_num[3] = tcphdr->ack_num[3];
	tcpchk->flag = tcphdr->flag;
	tcpchk->window_size = tcphdr->window_size;
	tcpchk->checksum = 0;
	tcpchk->urgent = tcphdr->urgent;

	tcphdr->checksum = tcp_checksum((unsigned short*)tcp_checkbuffer, sizeof(pseudo_header) + sizeof(tcp_header));
}

unsigned short ip_checksum(int ip_length, unsigned char buff[]) {

	unsigned short word16;
	unsigned int sum = 0;

	for (int i = 14; i < 14 + ip_length; i = i + 2) {

		word16 = ((buff[i] << 8) & 0xff00) + (buff[i + 1] & 0xff);
		sum = sum + (unsigned int)word16;
	}

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	sum = ~sum;

	return (unsigned short)sum;

}

unsigned short tcp_checksum(unsigned short *ptr, int nbytes) {

	register long sum;
	unsigned short oddbyte;
	register unsigned short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);

	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

