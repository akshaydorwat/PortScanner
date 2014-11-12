/**
 * Author    : Akshay Dorwat
 * Date      : 11-08-2014
 * Email     : adorwat@indiana.edu
 * Tab Width : 4 
 **/

#include "PacketFactory.hpp"

// Global declaration of static variable
bitset<MAX_PORT> PacketFactory::portRange;
Mutex PacketFactory::mLock;

bool PacketFactory::setOption(string option, void *ptr){
  
	bool ret;

    switch(protocol){
		
    case TCP :
		ret =  setOptionTCP(option, ptr);
		break;

    case ICMP:
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
		udp->check = udpChecksome(ptr);
	}else{
		LOG(ERROR, "Invalid Option TCP option :" + option);
		return false;
	}

	return true;
}

uint16_t PacketFactory::udpChecksome(struct UDP_pseudo_t *ptr){
	uint16_t sum;
	
	sum = checksumCalculator(ptr, sizeof(struct UDP_pseudo_t), 0);
	sum = checksumCalculator(packet, sizeof(struct udphdr), (uint16_t)~sum);
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
  // len is in bytes and we are using uin16_t so reducing length by 2 
  for(int i=len; i >= 2; i -= 2) {
    checksum += *(ptr++);
  }

  // Tricky and interesting part we need to add 16 MSB to 16 LSB
  checksum = (checksum >> 16) + (checksum & 0xffff);
  checksum += (checksum >> 16);

  // complement ckecksum
  return ((uint16_t)~checksum);
}


// get unused port 
uint16_t  PacketFactory::getUnusedPort(){
	
	int random;

	mLock.lock();
	srand (time(NULL));
	random = rand() % ( MIN_PORT + (MAX_PORT - MIN_PORT));
	
	if(portRange[random]){
		random++;
		if (random > MAX_PORT){
			random = MIN_PORT;
		}
	}
	portRange[random] = 1;
	mLock.unlock();
	return (uint16_t)random;
}

//free used port
void PacketFactory::freeUsedPort(uint16_t port){
	mLock.lock();
	portRange[(int)port] = 0;
	mLock.unlock();
}

