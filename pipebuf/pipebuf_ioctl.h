#ifndef PIPEBUF_IOCTL_H
#define PIPEBUF_IOCTL_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#endif

#define PIPEBUF_IOC_MAGIC 'P'
#define PIPEBUF_IOC_GET_BUFSIZE _IOR(PIPEBUF_IOC_MAGIC, 0, unsigned long)
#define PIPEBUF_IOC_SET_BUFSIZE _IOW(PIPEBUF_IOC_MAGIC, 1, unsigned long)

#endif
