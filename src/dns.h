#ifndef DNS_H
#define DNS_H

#include <sys/types.h>

/* copie from : http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets
 * Modifed to support endianess
 */

#define TYPE_A 0x0001

#define CLASS_INTERNET 0x0001

//DNS header structure
struct dnshdr
{
    uint16_t id; // identification number
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t rd :1; // recursion desired
    uint16_t tc :1; // truncated message
    uint16_t aa :1; // authoritive answer
    uint16_t opcode :4; // purpose of message
    uint16_t qr :1; // query/response flag
	uint16_t rcode :4; // response code
    uint16_t cd :1; // checking disabled
    uint16_t ad :1; // authenticated data
    uint16_t z :1; // its z! reserved
    uint16_t ra :1; // recursion available
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t qr :1; // query/response flag
	uint16_t opcode :4; // purpose of message
	uint16_t aa :1; // authoritive answer
    uint16_t tc :1; // truncated message
	uint16_t rd :1; // recursion desired
	uint16_t ra :1; // recursion available
	uint16_t z :1; // its z! reserved
	uint16_t ad :1; // authenticated data
	uint16_t cd :1; // checking disabled
	uint16_t rcode :4; // response code
# else
# error "Adjust your <bits/endian.h> defines"
#endif
    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct question
{
    uint16_t qtype;
    uint16_t qclass;
};

#endif
