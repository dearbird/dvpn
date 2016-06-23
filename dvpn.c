
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>  
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <getopt.h>

#include "fastlz.h"
#include "tap.h"

#define DEFAULT_LISTEN_PORT			8303
#define BOARDCAST_INTERVAL			10
#define RETRY_INTERVAL				3
#define MAC_LEN						6
#define MAX_IP_LEN					40
#define MAX_KEY_LEN					40
#define MAX_FRAME_LEN				2000
#define NODE_HASH_MASK				0x03FF


#define TYPE_ADDR					0
#define TYPE_ADDR_ACK				1
#define TYPE_ADDR_RELAY				2
#define TYPE_DATA					3

#define HEADER_LEN					2


typedef struct _SIPAddr
{
	struct _SIPAddr		*next;
	struct sockaddr_in	sa;
} SIPAddr;


typedef struct _SNode
{
	struct _SNode	*next;
	unsigned char	mac[MAC_LEN];
	SIPAddr			addr;
	unsigned int	delay;
} SNode;

static SNode *nodeMap[NODE_HASH_MASK +1];
//static SNode *nodeList = NULL;

static SIPAddr *localAddrList = NULL;
static SIPAddr *remoteAddrList = NULL;
static unsigned char localMAC[MAC_LEN];
static unsigned short listen_port = DEFAULT_LISTEN_PORT;

static int zip = 0;
//static int encrypt = 0;
//static char key[MAX_KEY_LEN];
static uint64_t time_now = 0ULL;
static uint64_t time_timeout = 0ULL;	
static int tap_fd = -1;
static int sock_fd = -1;

static uint64_t now();

static uint64_t now()
{
	struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)(ts.tv_sec *1000ULL + ts.tv_nsec/1000000);
}
static int isSameAddr(const struct sockaddr_in	*sa1, const struct sockaddr_in	*sa2)
{
	return (sa1->sin_port == sa2->sin_port) && (sa1->sin_addr.s_addr == sa2->sin_addr.s_addr);
}
static int hashfun(unsigned char *mac)
{
#define GET_UINT32(p)	((p[2]) |(p[3] << 8) |(p[4] << 16) |(p[5] << 24))
	int hash_val;

	hash_val = GET_UINT32(mac);
	hash_val ^= hash_val >> 16;
	hash_val ^= hash_val >> 8;
	hash_val ^= hash_val >> 3;

	return hash_val & NODE_HASH_MASK;
}

#define LOG_INFO	0
#define LOG_TRACE	5
static int log_level = 0;
static void LOG(int prio, const char *fmt, ...)
{
#define LOG_BUF_SIZE (4096)
	if(prio >= log_level)
	{
		va_list ap;
		char buf[LOG_BUF_SIZE]; 

		va_start(ap, fmt);
		vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
		va_end(ap);
		printf("<%d>: %s", prio, buf);		
	}
}

static int add_local_addr(const struct sockaddr_in  *sa)
{
	SIPAddr* addr = localAddrList;
	for(; addr; addr=addr->next)
	{
		if(isSameAddr(&addr->sa, sa))
			break;
	}
	if(addr == NULL)
	{
		addr = (SIPAddr*)malloc(sizeof(SIPAddr));
		memset(addr, 0, sizeof(SIPAddr));
		memcpy(&(addr->sa), sa, sizeof(struct sockaddr_in));
		addr->next = localAddrList;
		localAddrList = addr;
		LOG(LOG_INFO, "Local address %s:%d\n", inet_ntoa(addr->sa.sin_addr), ntohs(addr->sa.sin_port));
		return 0;
	}
	return -1;
}

static void get_all_local_addr()
{
    struct ifaddrs* ifa = NULL, *oifa;  
    if (getifaddrs(&ifa) < 0)  
    {  
		LOG(LOG_INFO, "Can't find local address.\n");
        return;  
    }  
    oifa = ifa;  
    while (ifa != NULL)  
    {  
        // IPv4 except lo
        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET && strncmp(ifa->ifa_name, "lo", 2) != 0)  
        {  
            struct sockaddr_in sa;
			memcpy(&sa, ifa->ifa_addr, sizeof(sa));
			sa.sin_port = htons(listen_port);
			add_local_addr(&sa);
        }  
        ifa = ifa->ifa_next;  
    }  
    freeifaddrs(oifa);
}
static int parse_addr(const char *str, struct sockaddr_in *sa)
{
	if(str)
	{
		char buf[MAX_IP_LEN];
		strcpy(buf, str);		
		char *p = strchr(buf, ':');
		if(p)
		{
			*p = 0;
			sa->sin_port = htons(atoi(p+1));
		}
		else
		{
			sa->sin_port = htons(DEFAULT_LISTEN_PORT);
		}
		sa->sin_addr.s_addr = inet_addr(buf);
		sa->sin_family = AF_INET;
		return 0;
	}
	return -1;	
}

static int socket_send(int fd, const unsigned char *buf, int len, struct sockaddr_in *sa)
{
	int sent = sendto( fd, buf, len, 0, (struct sockaddr *)sa, sizeof(struct sockaddr_in) );
    if (len != sent )
    {
        LOG(LOG_INFO, "sendto failed (%d) %s\n ", errno, strerror(errno));
		return -1;
    }

//	LOG(LOG_TRACE, "sendto %s:%d, type: %d, len:%d \n", inet_ntoa(sa->sin_addr), ntohs(sa->sin_port), buf[0], len);
	return 0;	
}

static int socket_broadcast(int fd, const unsigned char *buf, int len)
{
	if(remoteAddrList)
	{
		SIPAddr *addr = remoteAddrList;
		for(; addr; addr = addr->next)
		{
			socket_send(sock_fd, buf, len , &addr->sa);			
		}
		return 0;
	}
	
	for(int i=0; i <= NODE_HASH_MASK; ++i)
	{
		SNode *n = nodeMap[i];
		for(; n ; n = n->next)
		{
			// check alive
			if(n->delay < 3 * BOARDCAST_INTERVAL * 1000)
			{
				socket_send(sock_fd, buf, len , &n->addr.sa);
			}
		}
	}
	return 0;
}

static int process_timeout()
{
	if (time_now < time_timeout)	
    {
		return -1;
	}
	
	LOG(LOG_INFO, "process timeout %llu\n", time_now);
	
	for(int i=0; i <= NODE_HASH_MASK; ++i)
	{
		SNode *n = nodeMap[i];
		if(n == NULL)
		{
			continue;
		}
		if(n->next == NULL)	// only one node.
		{
			if(n->delay > 3*BOARDCAST_INTERVAL * 1000)
			{
				free(n);
				nodeMap[i] = NULL;
			}
		}
		else
		{
			do
			{
				if(n->next->delay > 3*BOARDCAST_INTERVAL * 1000)
				{
					free(n->next);
					n->next = n->next->next;
				}
			} while(n->next == NULL);
		}
		
		for(n = nodeMap[i]; n; n = n->next)
		{
			LOG(LOG_TRACE, "[%02X:%02X:%02X:%02X:%02X:%02X]  %s:%d, delay %u\n", 
				n->mac[0], n->mac[1], n->mac[2], n->mac[3], n->mac[4], n->mac[5],			
				inet_ntoa(n->addr.sa.sin_addr), ntohs(n->addr.sa.sin_port), n->delay );
				
			n->delay += BOARDCAST_INTERVAL * 1000;			
		}			
		
	}
	
	// do timeout
	int len = 0;
	unsigned char buffer[MAX_FRAME_LEN];
	SIPAddr *addr = localAddrList;
	for(;addr; addr = addr->next)
	{
		buffer[0] = TYPE_ADDR;
		memcpy(buffer + 1, localMAC, MAC_LEN);
		memcpy(buffer + 1 + MAC_LEN, &addr->sa, sizeof(struct sockaddr_in));
		memcpy(buffer + 1 + MAC_LEN + sizeof(struct sockaddr_in), (char*)&time_now, sizeof(unsigned long long));
		len = 1 + MAC_LEN + sizeof(struct sockaddr_in) + sizeof(unsigned long long);
		
		LOG(LOG_TRACE, "broadcast addr [%02X:%02X:%02X:%02X:%02X:%02X]  %s:%d, time: %llu\n",
			localMAC[0], localMAC[1], localMAC[2], localMAC[3], localMAC[4], localMAC[5],
			inet_ntoa(addr->sa.sin_addr), ntohs(addr->sa.sin_port), time_now);
			
		socket_broadcast(sock_fd, buffer, len);
	}
	
	//send_addr_update();
	time_timeout = time_now + BOARDCAST_INTERVAL * 1000 ;
	
	return 0;
}

static int process_tap_read()
{
	int len = 0;
	unsigned char buffer[MAX_FRAME_LEN];

	len = tap_read(tap_fd, buffer + HEADER_LEN, MAX_FRAME_LEN);
	if(len > 0)
	{
		unsigned char *dst = buffer + HEADER_LEN;
		buffer[0] = TYPE_DATA;
		buffer[1] = 0;
		
		if(dst[0] & 0x01) //broadcast
		{
			socket_broadcast(sock_fd, buffer, len + HEADER_LEN);
		}
		else		// unicast
		{
			int idx = hashfun(dst);
			SNode *n = nodeMap[idx];
			for(; n && memcmp(n->mac, dst, MAC_LEN); n = n->next);
			if(n)
			{
				socket_send(sock_fd, buffer, len + HEADER_LEN, &n->addr.sa);
			}	
		}
	}
	
	return 0;
}


static int process_socket_read()
{
	int len = 0;
	unsigned char buffer[MAX_FRAME_LEN];
	
    struct sockaddr_in  sa;
    size_t i = sizeof(sa);
	
    len = recvfrom(sock_fd, buffer, MAX_FRAME_LEN, 0, (struct sockaddr *)&sa, (socklen_t*)&i);
    if ( len < 0 )
    {
        LOG(LOG_INFO, "recvfrom failed with %s", strerror(errno));
        return -1;
    }
		
	int type  = buffer[0]&0x0F;
	
	//LOG(LOG_TRACE, "recv from  %s:%d, type:%d, len: %d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), type, len);
	
	switch(type)
	{
	case TYPE_DATA:
		{
			unsigned char *src = buffer + HEADER_LEN + MAC_LEN;
			int idx = hashfun(src);
			SNode *n = nodeMap[idx];
			for(; n && memcmp(n->mac, src, MAC_LEN); n = n->next);
			if(n == NULL)
			{
				n = (SNode*)malloc(sizeof(SNode));
				memcpy(n->mac, src, MAC_LEN);
				n->delay = BOARDCAST_INTERVAL;
				n->addr.next = NULL;
				n->next = nodeMap[idx];
				nodeMap[idx] = n;				
				
				LOG(LOG_TRACE, "addr find [%02X:%02X:%02X:%02X:%02X:%02X] %s:%d\n",
					src[0], src[1], src[2], src[3], src[4], src[5],				
					inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
			}
			n->addr.sa = sa;
			tap_write(tap_fd, buffer + HEADER_LEN, len - HEADER_LEN);
			break;
		}
	case TYPE_ADDR:
		{
			unsigned char *mac = buffer + 1;
			if(memcmp(mac, localMAC, MAC_LEN) == 0)
			{
				break;
			}
						
			buffer[0] = TYPE_ADDR_RELAY;
			socket_broadcast(sock_fd, buffer, len);	
			
			int idx = hashfun(mac);
			SNode *n = nodeMap[idx];
			for(; n && memcmp(n->mac, mac, MAC_LEN); n = n->next);
			if(n == NULL)
			{			
				n = (SNode*)malloc(sizeof(SNode));
				memcpy(n->mac, mac, MAC_LEN); 
				memcpy(&n->addr.sa, buffer + 1 + MAC_LEN, sizeof(struct sockaddr_in));
				n->delay = BOARDCAST_INTERVAL;	
				n->next = nodeMap[idx];
				nodeMap[idx] = n;
			}
			else
			{
				// replace with remote addr.
				memcpy(&n->addr.sa, &sa, sizeof(sa));				
			}
			
			LOG(LOG_TRACE, "recv addr  [%02X:%02X:%02X:%02X:%02X:%02X] %s:%d\n", 
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],				
				inet_ntoa(n->addr.sa.sin_addr), ntohs(n->addr.sa.sin_port));
			
			// send addr ack
			unsigned long long time_sent;
			memcpy(&time_sent, buffer + 1 + MAC_LEN + sizeof(struct sockaddr_in), sizeof(unsigned long long));
			buffer[0] = TYPE_ADDR_ACK;
			memcpy(buffer + 1, localMAC, MAC_LEN);
			memcpy(buffer + 1 + MAC_LEN, (char*)&time_sent, sizeof(unsigned long long));
			memcpy(buffer + 1 + MAC_LEN + sizeof(unsigned long long), &sa, sizeof(sa));
			len = 1 + MAC_LEN + sizeof(unsigned long long) + sizeof(sa);
			socket_send(sock_fd, buffer, len, &sa);	
			
			if(remoteAddrList != NULL)
			{
				while(remoteAddrList)
				{
					SIPAddr *s = remoteAddrList;
					remoteAddrList = remoteAddrList->next;
					free(s);
				}
			}
			break;
		}
	case TYPE_ADDR_ACK:
		{
			unsigned long long time_sent;			
			unsigned char *mac = buffer + 1;	
			
			memcpy(&time_sent, buffer + 1 + MAC_LEN, sizeof(unsigned long long));
			unsigned int delay = (unsigned int)(time_now - time_sent);
			
			int idx = hashfun(mac);
			SNode *n = nodeMap[idx];
			for(; n && memcmp(n->mac, mac, MAC_LEN); n = n->next);
			if(n == NULL)
			{
				n = (SNode*)malloc(sizeof(SNode));
				memcpy(n->mac, mac, MAC_LEN); 
				memcpy(&n->addr.sa, &sa, sizeof(sa)); 				
				n->delay = delay;	
				n->next = nodeMap[idx];
				nodeMap[idx] = n;
				
				LOG(LOG_TRACE, "addr ack [%02X:%02X:%02X:%02X:%02X:%02X] %s:%d, delay: %u\n",
					mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],				
				inet_ntoa(n->addr.sa.sin_addr), ntohs(n->addr.sa.sin_port), delay);
			}
			else if(n->delay > delay)
			{
				memcpy(&n->addr.sa, &sa, sizeof(sa)); 				
				n->delay = delay;
				
				LOG(LOG_TRACE, "addr ack [%02X:%02X:%02X:%02X:%02X:%02X] update to %s:%d, delay: %d\n",
					mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
					inet_ntoa(n->addr.sa.sin_addr), ntohs(n->addr.sa.sin_port), delay);
			}
			
			struct sockaddr_in l_sa;
			memcpy(&l_sa, buffer + 1 + MAC_LEN + sizeof(unsigned long long), sizeof(l_sa)); 
			add_local_addr(&l_sa);
			break;
		}
	case TYPE_ADDR_RELAY:
		{
			unsigned char *mac = buffer + 1;
			if(memcmp(mac, localMAC, MAC_LEN) == 0)
			{
				break;
			}
			
			int idx = hashfun(mac);
			SNode *n = nodeMap[idx];
			for(; n && memcmp(n->mac, mac, MAC_LEN); n = n->next);
			if(n == NULL)
			{			
				n = (SNode*)malloc(sizeof(SNode));
				memcpy(n->mac, mac, MAC_LEN); 
				memcpy(&n->addr.sa, buffer + 1 + MAC_LEN, sizeof(struct sockaddr_in));
				n->delay = BOARDCAST_INTERVAL;	
				n->next = nodeMap[idx];
				nodeMap[idx] = n;
			
				time_timeout = 0; 	// trigger broadcast immediately
				
				LOG(LOG_TRACE, "addr  [%02X:%02X:%02X:%02X:%02X:%02X] %s:%d\n", 
					mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],				
					inet_ntoa(n->addr.sa.sin_addr), ntohs(n->addr.sa.sin_port));
			}
			break;
		}
	default:
		LOG(LOG_INFO, "unknown data type from socket \n");
		break;
	}
	return 0;
}

int main(int argc, char* argv[])
{
	char 	tap_dev[MAX_IP_LEN] = "dvpn";
	char 	tap_addr[MAX_IP_LEN];
	
	struct sockaddr_in local_address;
	memset(&local_address, 0, sizeof(local_address));
	local_address.sin_family = AF_INET;
	
	int c;
	while((c = getopt(argc, argv, "p:a:d:l:r:zk:v")) != -1)
	{
		switch (c)
		{
		case 'p':
			listen_port = (unsigned short)atoi(optarg);
			break;
		case 'a':
			strcpy(tap_addr, optarg);
			break;
		case 'd':
			strcpy(tap_dev, optarg);
			break;
		case 'z':
			zip = 1;
			break;
		case 'r':
			{
				LOG(LOG_INFO, "-r %s\n", optarg);
				SIPAddr *addr = (SIPAddr*)malloc(sizeof(SIPAddr));
				memset(addr, 0, sizeof(SIPAddr));
				if(parse_addr(optarg, &addr->sa) ==0)
				{
					addr->next = remoteAddrList;
					remoteAddrList = addr;
				}
				else
				{
					free(addr);
					LOG(LOG_INFO, "invalid addres %s\n", optarg);
				}
				break;
			}
		case 'l':
			{
				LOG(LOG_INFO, "-l %s\n", optarg);
				struct sockaddr_in	sa;
				
				if(parse_addr(optarg, &sa) ==0)
				{
					add_local_addr(&sa);
				}
				else
				{
					LOG(LOG_INFO, "invalid addres %s\n", optarg);
				}
				break;
			}
			
		case 'v':
			log_level ++;
			break;
		}
	}
	
	get_all_local_addr();
	
	local_address.sin_port = htons(listen_port);
	local_address.sin_addr.s_addr = htonl(INADDR_ANY);
	sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if(sock_fd  < 0) {
		LOG(LOG_INFO, "Unable to create socket [%s][%d]\n", strerror(errno), sock_fd);
		return -1;
	}
	
	int sockopt = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

	if(bind(sock_fd, (struct sockaddr*) &local_address, sizeof(local_address)) == -1) {
		LOG(LOG_INFO, "Bind error [%s]\n", strerror(errno));
		return -1;
	}
	
	// open tap;
	tap_fd = tap_open(tap_dev, tap_addr, localMAC);
	if(tap_fd < 0)
	{
		LOG(LOG_INFO, "Can't open tap device.\n");
		close(sock_fd);
		return -1;
	}
	
	
	while (1)
	{	
        int rc;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock_fd, &fds);
        FD_SET(tap_fd, &fds);

		
        struct timeval tv;
        tv.tv_sec = 1; tv.tv_usec = 0;		
        rc = select(tap_fd + 1, &fds, NULL, NULL, &tv);
		
		time_now = now();
        process_timeout();	
		
        if(rc > 0)
        {
            if(FD_ISSET(tap_fd, &fds))
            {
				process_tap_read();				
            }
			else if(FD_ISSET(sock_fd, &fds))
            {
				process_socket_read();
            }
        }


    } /* while */
	
	return 0;
}
