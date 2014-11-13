/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "PacketFactory.hpp"

bool PacketFactory::setOption(string option, void *ptr){
  
	bool ret;

    switch(protocol){
		
    case TCP :
		ret =  setOptionTCP(option, ptr);
		break;

    case DNS:
		ret = setOptionDNS(option, ptr);
		break;

    case UDP:
		ret = setOptionUDP(option, ptr);
		break;
		
    default:
		LOG(ERROR, "Invalid Protocol");
		ret = false;
    }
	return ret;
}

bool PacketFactory::setOptionDNS(string &option, void *val){

	struct dnshdr *dns = (struct dnshdr *)(packet + sizeof(udphdr));
	
	// source port
	if(option.compare("src_port") == 0){
		setOptionUDP(option, val);
	} else

	// destination port
	if(option.compare("dst_port") == 0){
		setOptionUDP(option, val);
	} else

	// length
	if(option.compare("len") == 0){				
		setOptionUDP(option, val);
	}else

	// checksum
	if(option.compare("check") == 0){
		setOptionUDP(option, val);
	}else
	
	// unique dns request id
	if(option.compare("id") == 0){
		uint16_t *id = (uint16_t *)val;
		dns->q_count = htons(*id);
	}else

	// recursion desired
	if(option.compare("rd") == 0){
		dns->rd = 1;
	}else

	// truncate causion
	if(option.compare("tc") == 0){
		dns->tc = 1;
	}else

	// authorative answer
	if(option.compare("aa") == 0){
		dns->aa = 1;
	}else

	// opcode
	if(option.compare("opcode") == 0){
		uint16_t *opcode = (uint16_t*)val;
		dns->opcode = *opcode;
	}else

	// query/response
	if(option.compare("qr") == 0){
		dns->qr = 1;
	}else

	//resonse code
	if(option.compare("rcode") == 0){
		uint16_t *rcode = (uint16_t*)val;
		dns->rcode = *rcode;
	}else

	// checking disable
	if(option.compare("cd") == 0){
		dns->cd = 1;
	}else

	// authenticated data
	if(option.compare("ad") == 0){
		dns->ad = 1;
	}else

	// recusion available
	if(option.compare("ra") == 0){
		dns->ra = 1;
	}else

	// question count
	if(option.compare("q_count") == 0){
		uint16_t *count = (uint16_t *)val;
		dns->q_count = htons(*count);
	}else

	// answer count
	if(option.compare("ans_count") == 0){
		uint16_t *count = (uint16_t *)val;
		dns->ans_count = htons(*count);
	}else

	// authority count
	if(option.compare("auth_count") == 0){
		uint16_t *count = (uint16_t *)val;
		dns->auth_count = htons(*count);
	}else
	
	// resource entry count
	if(option.compare("add_count") == 0){
		uint16_t *count = (uint16_t *)val;
		dns->add_count = htons(*count);
	}else{
		LOG(ERROR, "Invalid UDP option " + option);
		return false;
	}

	return true;
}


int PacketFactory::setQuestion(char *str,  uint16_t qtype, uint16_t qclass){
	
	struct question * qinfo;
	char *qname;
	int qname_len;

	// error check
	if(protocol != DNS){
		LOG(ERROR, "Protocol set is not DNS");
		return 0;
	}

	// calculate question name pointer pointer 
	qname = (char *)(packet + sizeof(udphdr) + sizeof(dnshdr));
	
	// convert string to dns string
	qname_len = charToDnsString(str, qname);
	
	// quesion section 
	qinfo = (struct question *)(packet + sizeof(udphdr) + sizeof(dnshdr) + qname_len);
	qinfo->qtype = qtype;
	qinfo->qclass = qclass;

	return qname_len;
}


int PacketFactory::charToDnsString(char *str, char *dns){

    char buff[1024];
    char *ptr;
    int len;

    memcpy( buff, str, strlen(str));
    ptr = strtok(buff, ".");
    while(ptr != NULL){
        // determine the length                                                                                  
        printf("string : %s \n",ptr);
        len = strlen(ptr);
        //copy length                                                                                             
        *dns++ = len;
        // copy string into dns buffer                                           
        memcpy(dns, ptr, len);
        //increment dns pointer by string len                                                                     
        dns = dns + len;
        // iterative call to strtok                                                                               
        ptr = strtok (NULL, ".");
    }
    *dns++ = '\0';
	return strlen(dns)+1;
}

bool PacketFactory::setOptionUDP(string &option, void *val){
	struct udphdr *udp = (struct udphdr*)packet;

	// source port
	if(option.compare("src_port") == 0){
		uint16_t *port = (uint16_t*)val;
		udp->source = htons(*port);
	} else

	// destination port
	if(option.compare("dst_port") == 0){
		uint16_t *port = (uint16_t*)val;
		udp->dest = htons(*port);
	} else

	// length
	if(option.compare("len") == 0){				
		uint16_t *len = (uint16_t*)val;
		udp->len = htons(*len);
	}else

	// checksum
	if(option.compare("check") == 0){
		struct UDP_pseudo_t *ptr = (struct UDP_pseudo_t *)val;
		udp->check = udpChecksome(ptr, (int)ntohs(udp->len));
	}else{
		LOG(ERROR, "Invalid Option UDP option :" + option);
		return false;
	}

	return true;
}

uint16_t PacketFactory::udpChecksome(struct UDP_pseudo_t *ptr, int hdr_len){
	uint16_t sum;
	
	sum = checksumCalculator(ptr, sizeof(struct UDP_pseudo_t), 0);
	sum = checksumCalculator(packet, hdr_len, (uint16_t)~sum);
	return sum;
}

bool PacketFactory::setOptionTCP(string &option, void *val){

	struct tcphdr *tcp = (struct tcphdr*)packet;
	
	// source port
	if(option.compare("src_port") == 0){
		uint16_t *port = (uint16_t*)val;
		tcp->source = htons(*port);
	} else

	// destination port
	if(option.compare("dst_port") == 0){
		uint16_t *port = (uint16_t*)val;
		tcp->dest = htons(*port);
	} else

	// sequence number
	if(option.compare("seq_no") == 0){				
		uint32_t *seq = (uint32_t*)val;
		tcp->seq = htonl(*seq);
	}else

	// acknowlegement  sequence number
	if(option.compare("ack_seq") == 0){
		uint16_t *ack_seq = (uint16_t*)val;
		tcp->ack_seq = htons(*ack_seq);
	}else
	
	// data offset
	if(option.compare("doff") == 0){
		uint16_t *doff = (uint16_t*)val;
		tcp->doff = *doff;
	}else

	// finish flag
	if(option.compare("fin") == 0){
		tcp->fin = 1;
	}else

	// synchronize flag
	if(option.compare("syn") == 0){
		tcp->syn = 1;
	}else

	// reset flag
	if(option.compare("rst") == 0){
		tcp->rst = 1;
	}else

	// push flag
	if(option.compare("psh") == 0){
		tcp->psh = 1;
	}else

	// acknowledgement flag
	if(option.compare("ack") == 0){
		tcp->ack = 1;
	}else
	
	// urgent pointer flag
	if(option.compare("urg") == 0){
		tcp->urg = 1;
	}else

	// window size
	if(option.compare("window") == 0){
		uint16_t *window = (uint16_t *)val;
		tcp->window = htons(*window);
	}else

	// checksum
	if(option.compare("check") == 0){
		struct TCP_pseudo_t *ptr = (struct TCP_pseudo_t *)val;
		tcp->check = tcpChecksome(ptr);
	}else
	
	// urgent sequence number
	if(option.compare("urg_ptr") == 0){
		uint16_t *urg_ptr = (uint16_t *)val;
		tcp->urg_ptr = htons(*urg_ptr);
	}else{
		LOG(ERROR, "Invalid Option TCP option :" + option);
		return false;
	}

	return true;
}


uint16_t PacketFactory::tcpChecksome(struct TCP_pseudo_t *ptr){
	uint16_t sum;
	
	sum = checksumCalculator(ptr, sizeof(struct TCP_pseudo_t), 0);
	sum = checksumCalculator(packet, sizeof(struct tcphdr), (uint16_t)~sum);
	return sum;
}

uint16_t PacketFactory::checksumCalculator (const void * addr, uint32_t len, uint16_t init) {
  uint32_t checksum;
  // checksum is 16 bit one's complement
  const uint16_t * ptr;
  checksum = init;
  ptr = (uint16_t *) addr;
  
  // calcualte the some over the packet
  // len is in bytes and we are using uint16_t so reducing length by 2 
  for(int i=len; i >= 2; i -= 2) {
    checksum += *(ptr++);
  }

  // Tricky and interesting part we need to add 16 MSB to 16 LSB
  checksum = (checksum >> 16) + (checksum & 0xffff);
  checksum += (checksum >> 16);

  // complement ckecksum
  return ((uint16_t)~checksum);
}


