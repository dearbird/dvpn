
#include "tap.h"


int tap_open(const char *dev, const char *pcIP, unsigned char *pcMac)
{
	int iMTU = 1400;	
    char acBuf[128];
    struct ifreq ifr;
    int fd;
    
    fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0) {
        printf("ERROR: open tun device failed [%s][%d]\n", strerror(errno), errno);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP|IFF_NO_PI; /* Want a TAP device for layer 2 frames. */
    strncpy(ifr.ifr_name, dev ? dev: "", IFNAMSIZ);
    if( ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        printf("ioctl TUNSETIFF error [%s ]\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Dummy socket, just to make ioctls with */
    int iSocket =socket(PF_INET, SOCK_DGRAM, 0);
  
    if( ioctl(iSocket, SIOCGIFHWADDR, &ifr)  < 0)
    {
        printf("Get HW addr error [%s]\n", strerror(errno));
        close(iSocket);
        close(fd);
        return -1;
    } 
    else
    {
        close(iSocket);
        memcpy(pcMac, (char *)ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
    }
    printf("Open device [name=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X]\n", dev, 
        (unsigned char)pcMac[0], 
        (unsigned char)pcMac[1],
        (unsigned char)pcMac[2], 
        (unsigned char)pcMac[3],
        (unsigned char)pcMac[4], 
        (unsigned char)pcMac[05]);
		
    if ( pcIP == NULL || strlen(pcIP) == 0 )
    {
        snprintf(acBuf, sizeof(acBuf), "/sbin/ifconfig %s mtu %d up",
            ifr.ifr_name, iMTU);
    }
    else
    {
        snprintf(acBuf, sizeof(acBuf), "/sbin/ifconfig %s %s mtu %d up",
            ifr.ifr_name, pcIP, iMTU);
    }

    if(!system(acBuf))
    {
        printf("Bringing up: %s\n", acBuf);
    }
    return fd;
}


int tap_read(int fd,  unsigned char *pcBuf, int iLen)
{
    return read(fd, pcBuf, iLen);
}


int tap_write(int fd, const unsigned char *pcBuf, int iLen)
{
    return write(fd, pcBuf, iLen);
}


void tap_close(int fd) 
{
    close(fd);
}


