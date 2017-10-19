typedef unsigned int __darwin_natural_t;
typedef __darwin_natural_t natural_t;
typedef unsigned int boolean_t;

typedef struct mach_port_qos {
 unsigned int name:1;
 unsigned int prealloc:1;
 boolean_t pad1:30;
 natural_t len;
} mach_port_qos_t;

