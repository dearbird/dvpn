
#ifndef __TAP_H
#define __TAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define INVALID_VLNTAP_HANDLE -1

#define TAP_MAC_SIZE 6

int tap_open(const char *dev, const char *pcIP, unsigned char *pcMac);
int tap_read(int fd, unsigned char *pcBuf, int iLen);
int tap_write(int fd, const unsigned char *pcBuf, int iLen);
void tap_close(int fd);

#endif 

