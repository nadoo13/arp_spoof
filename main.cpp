#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

void usage() {
	printf("syntax: arp_send <interface> <send ip> <target ip>\n");
	printf("sample: arp_send wlan0 <192.168.43.117> <192.168.43.1>\n");
}

int getIPaddr(char *ip_addr) {
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		dp(4, "socket");
		return 0;
	}

	strcpy(ifr.ifr_name, "eth0");
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0)  
	{
		dp(4, "ioctl() - get ip");
		close(sock);
		return 0;
	}
	
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	strcpy(ip_addr, inet_ntoa(sin->sin_addr));
	
	close(sock);
	return 1;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    char c=0;
    printf("default interface name : enp0s3, okay? y/n\n");
    scanf("%c",&c);
    if(c=='y') {
      argv[1]="enp0s3";
    }
    else {
      usage();
      return -1;
    }
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printf("src MAC : ");
    for(int i=6;i<12;i++) { printf("%02x ",packet[i]);}
    printf("\n");
    printf("dest MAC : ");
    for(int i=0;i<6;i++) { printf("%02x ",packet[i]);}
    printf("\n");
    uint16_t eth_type = (packet[12]<<8) + packet[13];
    printf("type : %04x\n",eth_type);

  }



  pcap_close(handle);
  return 0;
}
