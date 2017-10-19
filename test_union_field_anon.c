typedef unsigned char __uint8_t;
typedef unsigned short __uint16_t;
typedef int __int32_t;
typedef unsigned int __uint32_t;


struct in6_addr {
	union {
	 __uint8_t __u6_addr8[16];
	 __uint16_t __u6_addr16[8];
	 __uint32_t __u6_addr32[4];
	} __u6_addr;
};

