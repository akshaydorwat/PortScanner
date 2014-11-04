#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

using namespace std;

struct TCP_pseudo{
  u_int32_t saddr;
  u_int32_t daddr;
  u_int8_t reserve;
  u_int8_t protocol;
  u_int16_t len;
};

uint16_t in_cksum (const void * addr, unsigned len, uint16_t init) {
  uint32_t sum;
  const uint16_t * word;
  sum = init;
  word = (uint16_t *) addr;

  while (len >= 2) {
    sum += *(word++);
    len -= 2;
  }

  if (len > 0) {
    uint16_t tmp;

    *(uint8_t *)(&tmp) = *(uint8_t *)word;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ((uint16_t)~sum);
}



int main(int argc, char *argv[])
{
  int raw;
  int zero = 0;
  int count;
  char buff[2048];
  struct sockaddr_in dst;
  struct tcphdr *tcp = (struct tcphdr*)buff;
  const int *val = &zero;
  int fd;
  struct ifreq ifr;
  u_int16_t sum;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  /* I want to get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;
  /* I want IP address attached to "eth0" */
  strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);

  /* display result */
  printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  
  // create raw socket
  raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if(raw < 0 ){
    cout << "Failed to create RAW socket";
    exit(0);
  }else{
    cout << "Socket Initialized";
  }

  // set IPHDRINCL fasle
  if(setsockopt(raw, IPPROTO_IP, IP_HDRINCL, val, sizeof(zero)) < 0){
      cout <<"setsockopt() error";
      exit(-1);
  }else{
    cout << "setsockopt() is OK\n";
  }
  
  //set dest address
  dst.sin_family = AF_INET;
  dst.sin_port = htons(80);
  dst.sin_addr.s_addr = inet_addr("10.0.0.88");  

  tcp->source = htons(34805);
  tcp->dest = htons(80);
  tcp->seq = htonl(4);
  tcp->ack_seq = 0;
  tcp->doff = 5;
  tcp->syn = 1;
  tcp->window = htons(29200);
  tcp->check = 0;
  tcp->urg_ptr = 0;

  struct TCP_pseudo t;
  t.saddr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
  t.daddr = inet_addr("10.0.0.44");
  t.reserve = 0;
  t.protocol = 6;
  t.len = htons(sizeof(struct tcphdr));
  sum = in_cksum(&t, sizeof(t), 0);

  sum = in_cksum(tcp, sizeof(struct tcphdr), (uint16_t)~sum);
  tcp->check = sum;

  for(count = 0; count < 5; count++){
    if(sendto(raw, buff, sizeof(struct tcphdr), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){
      cout << "sendto() error";
      exit(-1);
    }else{
      cout << "Count " <<count <<" - sendto() is OK\n";
      sleep(2);
    }
  }

  char buffer[8192]; /* single packets are usually not bigger than 8192 bytes */
  while (read (raw, buffer, 8192) > 0){
    struct ip * i = (struct ip *) buffer;
    struct tcphdr *h =  (struct tcphdr *) buffer+sizeof(struct iphdr);
    cout << "source ip : " << inet_ntoa((i->ip_src)) <<endl; 
    cout << "dest ip : " << inet_ntoa((i->ip_dst)) <<endl; 
    printf("Source port : %u \n", ntohs(h->source));
    printf("Dest  port : %u \n", ntohs(h->dest));
    
    if(h->syn){
      printf(" TH_SYN => True\n");
    }

    
    if(h->rst){
      printf(" TH_RST => True\n");
    }
  
    if(h->psh){
      printf(" TH_PUSH => True\n");
    }
  
    if(h->ack){
      printf(" TH_ACK => True\n");
    }
  }
  
  close(raw);
  return 0;
}
