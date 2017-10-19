typedef unsigned u_int32_t;
struct __ifnet;
typedef struct __ifnet* ifnet_t; // no pointer
typedef u_int32_t protocol_family_t;

struct ifnet_demux_desc {
 u_int32_t type;
 void *data;
 u_int32_t datalen;
};


typedef int (*ifnet_add_proto_func)(ifnet_t interface,
    protocol_family_t protocol_family,
    const struct ifnet_demux_desc *demux_array, u_int32_t demux_count);

typedef char * p_char;
