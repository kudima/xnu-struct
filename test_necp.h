

typedef signed char __int8_t;



typedef unsigned char __uint8_t;
typedef short __int16_t;
typedef unsigned short __uint16_t;
typedef int __int32_t;
typedef unsigned int __uint32_t;
typedef long long __int64_t;
typedef unsigned long long __uint64_t;

typedef long __darwin_intptr_t;
typedef unsigned int __darwin_natural_t;
typedef int __darwin_ct_rune_t;





typedef union {
 char __mbstate8[128];
 long long _mbstateL;
} __mbstate_t;

typedef __mbstate_t __darwin_mbstate_t;


typedef long int __darwin_ptrdiff_t;







typedef long unsigned int __darwin_size_t;





typedef __builtin_va_list __darwin_va_list;





typedef int __darwin_wchar_t;




typedef __darwin_wchar_t __darwin_rune_t;


typedef int __darwin_wint_t;




typedef unsigned long __darwin_clock_t;
typedef __uint32_t __darwin_socklen_t;
typedef long __darwin_ssize_t;
typedef long __darwin_time_t;
typedef __int64_t __darwin_blkcnt_t;
typedef __int32_t __darwin_blksize_t;
typedef __int32_t __darwin_dev_t;
typedef unsigned int __darwin_fsblkcnt_t;
typedef unsigned int __darwin_fsfilcnt_t;
typedef __uint32_t __darwin_gid_t;
typedef __uint32_t __darwin_id_t;
typedef __uint64_t __darwin_ino64_t;



typedef __uint32_t __darwin_ino_t;

typedef __darwin_natural_t __darwin_mach_port_name_t;
typedef __darwin_mach_port_name_t __darwin_mach_port_t;
typedef __uint16_t __darwin_mode_t;
typedef __int64_t __darwin_off_t;
typedef __int32_t __darwin_pid_t;
typedef __uint32_t __darwin_sigset_t;
typedef __int32_t __darwin_suseconds_t;
typedef __uint32_t __darwin_uid_t;
typedef __uint32_t __darwin_useconds_t;
typedef unsigned char __darwin_uuid_t[16];
typedef char __darwin_uuid_string_t[37];
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned long long u_int64_t;


typedef int64_t register_t;






typedef __darwin_intptr_t intptr_t;
typedef unsigned long uintptr_t;



typedef u_int64_t user_addr_t;
typedef u_int64_t user_size_t;
typedef int64_t user_ssize_t;
typedef int64_t user_long_t;
typedef u_int64_t user_ulong_t;
typedef int64_t user_time_t;
typedef int64_t user_off_t;
typedef __uint64_t user64_addr_t __attribute__((aligned(8)));
typedef __uint64_t user64_size_t __attribute__((aligned(8)));
typedef __int64_t user64_ssize_t __attribute__((aligned(8)));
typedef __int64_t user64_long_t __attribute__((aligned(8)));
typedef __uint64_t user64_ulong_t __attribute__((aligned(8)));
typedef __int64_t user64_time_t __attribute__((aligned(8)));
typedef __int64_t user64_off_t __attribute__((aligned(8)));

typedef __uint32_t user32_addr_t;
typedef __uint32_t user32_size_t;
typedef __int32_t user32_ssize_t;
typedef __int32_t user32_long_t;
typedef __uint32_t user32_ulong_t;
typedef __int32_t user32_time_t;
typedef __int64_t user32_off_t __attribute__((aligned(4)));





typedef u_int64_t syscall_arg_t;
typedef u_int8_t uint8_t;
typedef u_int16_t uint16_t;
typedef u_int32_t uint32_t;
typedef u_int64_t uint64_t;



typedef int8_t int_least8_t;
typedef int16_t int_least16_t;
typedef int32_t int_least32_t;
typedef int64_t int_least64_t;
typedef uint8_t uint_least8_t;
typedef uint16_t uint_least16_t;
typedef uint32_t uint_least32_t;
typedef uint64_t uint_least64_t;



typedef int8_t int_fast8_t;
typedef int16_t int_fast16_t;
typedef int32_t int_fast32_t;
typedef int64_t int_fast64_t;
typedef uint8_t uint_fast8_t;
typedef uint16_t uint_fast16_t;
typedef uint32_t uint_fast32_t;
typedef uint64_t uint_fast64_t;
typedef long long intmax_t;
typedef unsigned long long uintmax_t;


typedef __uint32_t in_addr_t;

typedef __uint16_t in_port_t;






static __inline__ unsigned short ntohs(unsigned short);
static __inline__
unsigned short
ntohs(unsigned short w_int)
{
 return ((w_int << 8) | (w_int >> 8));
}



unsigned short htons(unsigned short);




static __inline__ unsigned long ntohl(unsigned long);
static __inline__
unsigned long
ntohl(unsigned long value)
{

 return (unsigned long)__builtin_bswap32((unsigned int)value);





}



unsigned long htonl(unsigned long);


typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

typedef unsigned long u_long;


typedef unsigned short ushort;
typedef unsigned int uint;


typedef u_int64_t u_quad_t;
typedef int64_t quad_t;
typedef quad_t * qaddr_t;


typedef char * caddr_t;

typedef int32_t daddr_t;


typedef __darwin_dev_t dev_t;

typedef u_int32_t fixpt_t;


typedef __darwin_blkcnt_t blkcnt_t;
typedef __darwin_blksize_t blksize_t;
typedef __darwin_gid_t gid_t;


typedef __darwin_ino_t ino_t;


typedef __darwin_ino64_t ino64_t;


typedef __int32_t key_t;
typedef __darwin_mode_t mode_t;
typedef __uint16_t nlink_t;
typedef __darwin_id_t id_t;
typedef __darwin_pid_t pid_t;
typedef __darwin_off_t off_t;

typedef int32_t segsz_t;
typedef int32_t swblk_t;


typedef __darwin_uid_t uid_t;
typedef __darwin_clock_t clock_t;
typedef __darwin_size_t size_t;
typedef __darwin_ssize_t ssize_t;
typedef __darwin_time_t time_t;

typedef __darwin_useconds_t useconds_t;
typedef __darwin_suseconds_t suseconds_t;


typedef __darwin_size_t rsize_t;
typedef int errno_t;








typedef struct fd_set {
 __int32_t fds_bits[((((1024) % ((sizeof(__int32_t) * 8))) == 0) ? ((1024) / ((sizeof(__int32_t) * 8))) : (((1024) / ((sizeof(__int32_t) * 8))) + 1))];
} fd_set;



static __inline int
__darwin_fd_isset(int _n, const struct fd_set *_p)
{
 return (_p->fds_bits[(unsigned long)_n/(sizeof(__int32_t) * 8)] & ((__int32_t)(((unsigned long)1)<<((unsigned long)_n % (sizeof(__int32_t) * 8)))));
}




typedef __int32_t fd_mask;










typedef __darwin_fsblkcnt_t fsblkcnt_t;
typedef __darwin_fsfilcnt_t fsfilcnt_t;

typedef __uint8_t sa_family_t;
typedef __darwin_socklen_t socklen_t;
struct iovec {
 void * iov_base;
 size_t iov_len;
};
typedef __uint32_t sae_associd_t;



typedef __uint32_t sae_connid_t;
typedef struct sa_endpoints {
 unsigned int sae_srcif;
 const struct sockaddr *sae_srcaddr;
 socklen_t sae_srcaddrlen;
 const struct sockaddr *sae_dstaddr;
 socklen_t sae_dstaddrlen;
} sa_endpoints_t;





struct linger {
 int l_onoff;
 int l_linger;
};
struct so_np_extensions {
 u_int32_t npx_flags;
 u_int32_t npx_mask;
};
struct sockaddr {
 __uint8_t sa_len;
 sa_family_t sa_family;
 char sa_data[14];
};
struct sockproto {
 __uint16_t sp_family;
 __uint16_t sp_protocol;
};
struct sockaddr_storage {
 __uint8_t ss_len;
 sa_family_t ss_family;
 char __ss_pad1[((sizeof(__int64_t)) - sizeof(__uint8_t) - sizeof(sa_family_t))];
 __int64_t __ss_align;
 char __ss_pad2[(128 - sizeof(__uint8_t) - sizeof(sa_family_t) - ((sizeof(__int64_t)) - sizeof(__uint8_t) - sizeof(sa_family_t)) - (sizeof(__int64_t)))];
};
struct msghdr {
 void *msg_name;
 socklen_t msg_namelen;
 struct iovec *msg_iov;
 int msg_iovlen;
 void *msg_control;
 socklen_t msg_controllen;
 int msg_flags;
};
struct cmsghdr {
 socklen_t cmsg_len;
 int cmsg_level;
 int cmsg_type;

};
struct sf_hdtr {
 struct iovec *headers;
 int hdr_cnt;
 struct iovec *trailers;
 int trl_cnt;
};



struct user_sf_hdtr {
 user_addr_t headers;
 int hdr_cnt;
 user_addr_t trailers;
 int trl_cnt;
};


struct user64_sf_hdtr {
 user64_addr_t headers;
 int hdr_cnt;
 user64_addr_t trailers;
 int trl_cnt;
};


struct user32_sf_hdtr {
 user32_addr_t headers;
 int hdr_cnt;
 user32_addr_t trailers;
 int trl_cnt;
};







typedef int64_t daddr64_t;


struct buf;
typedef struct buf * buf_t;

struct file;
typedef struct file * file_t;






struct mount;
typedef struct mount * mount_t;

struct vnode;
typedef struct vnode * vnode_t;

struct proc;
typedef struct proc * proc_t;

struct uio;
typedef struct uio * uio_t;

struct vfs_context;
typedef struct vfs_context * vfs_context_t;

struct vfstable;
typedef struct vfstable * vfstable_t;

struct __ifnet;
struct __mbuf;
struct __pkthdr;
struct __socket;
struct __sockopt;
struct __ifaddr;
struct __ifmultiaddr;
struct __ifnet_filter;
struct __rtentry;
struct __if_clone;
struct __bufattr;

typedef struct __ifnet* ifnet_t;
typedef struct __mbuf* mbuf_t;
typedef struct __pkthdr* pkthdr_t;
typedef struct __socket* socket_t;
typedef struct __sockopt* sockopt_t;
typedef struct __ifaddr* ifaddr_t;
typedef struct __ifmultiaddr* ifmultiaddr_t;
typedef struct __ifnet_filter* interface_filter_t;
typedef struct __rtentry* route_t;
typedef struct __if_clone* if_clone_t;
typedef struct __bufattr* bufattr_t;
typedef struct {

 unsigned char g_guid[16];
} guid_t;



struct kauth_ace;
typedef struct kauth_ace * kauth_ace_t;



struct kauth_acl;
typedef struct kauth_acl * kauth_acl_t;



struct kauth_filesec;
typedef struct kauth_filesec * kauth_filesec_t;




typedef int kauth_action_t;



struct timeval;
typedef void (*sock_upcall)(socket_t so, void *cookie, int waitf);
extern errno_t sock_accept(socket_t so, struct sockaddr *from, int fromlen,
    int flags, sock_upcall callback, void *cookie, socket_t *new_so);
extern errno_t sock_bind(socket_t so, const struct sockaddr *to);
extern errno_t sock_connect(socket_t so, const struct sockaddr *to, int flags);
extern errno_t sock_getpeername(socket_t so, struct sockaddr *peername,
    int peernamelen);
extern errno_t sock_getsockname(socket_t so, struct sockaddr *sockname,
    int socknamelen);
extern errno_t sock_getsockopt(socket_t so, int level, int optname,
    void *optval, int *optlen);
extern errno_t sock_ioctl(socket_t so, unsigned long request, void *argp);
extern errno_t sock_setsockopt(socket_t so, int level, int optname,
    const void *optval, int optlen);
extern errno_t sock_listen(socket_t so, int backlog);
extern errno_t sock_receive(socket_t so, struct msghdr *msg, int flags,
    size_t *recvdlen);
extern errno_t sock_receivembuf(socket_t so, struct msghdr *msg, mbuf_t *data,
    int flags, size_t *recvlen);
extern errno_t sock_send(socket_t so, const struct msghdr *msg, int flags,
    size_t *sentlen);
extern errno_t sock_sendmbuf(socket_t so, const struct msghdr *msg, mbuf_t data,
    int flags, size_t *sentlen);
extern errno_t sock_shutdown(socket_t so, int how);
extern errno_t sock_socket(int domain, int type, int protocol,
    sock_upcall callback, void *cookie, socket_t *new_so);
extern void sock_close(socket_t so);
extern errno_t sock_setpriv(socket_t so, int on);







extern int sock_isconnected(socket_t so);
extern int sock_isnonblocking(socket_t so);
extern errno_t sock_gettype(socket_t so, int *domain, int *type, int *protocol);





struct in_addr {
 in_addr_t s_addr;
};
struct sockaddr_in {
 __uint8_t sin_len;
 sa_family_t sin_family;
 in_port_t sin_port;
 struct in_addr sin_addr;
 char sin_zero[8];
};
struct ip_opts {
 struct in_addr ip_dst;
 char ip_opts[40];
};
struct ip_mreq {
 struct in_addr imr_multiaddr;
 struct in_addr imr_interface;
};






struct ip_mreqn {
 struct in_addr imr_multiaddr;
 struct in_addr imr_address;
 int imr_ifindex;
};




struct ip_mreq_source {
 struct in_addr imr_multiaddr;
 struct in_addr imr_sourceaddr;
 struct in_addr imr_interface;
};





struct group_req {
 uint32_t gr_interface;
 struct sockaddr_storage gr_group;
};

struct group_source_req {
 uint32_t gsr_interface;
 struct sockaddr_storage gsr_group;
 struct sockaddr_storage gsr_source;
};
struct __msfilterreq {
 uint32_t msfr_ifindex;
 uint32_t msfr_fmode;
 uint32_t msfr_nsrcs;
 uint32_t __msfr_align;
 struct sockaddr_storage msfr_group;
 struct sockaddr_storage *msfr_srcs;
};



struct sockaddr;
struct in_pktinfo {
 unsigned int ipi_ifindex;
 struct in_addr ipi_spec_dst;
 struct in_addr ipi_addr;
};
struct in6_addr {
 union {
  __uint8_t __u6_addr8[16];
  __uint16_t __u6_addr16[8];
  __uint32_t __u6_addr32[4];
 } __u6_addr;
};
struct sockaddr_in6 {
 __uint8_t sin6_len;
 sa_family_t sin6_family;
 in_port_t sin6_port;
 __uint32_t sin6_flowinfo;
 struct in6_addr sin6_addr;
 __uint32_t sin6_scope_id;
};
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;

extern const struct in6_addr in6addr_nodelocal_allnodes;
extern const struct in6_addr in6addr_linklocal_allnodes;
extern const struct in6_addr in6addr_linklocal_allrouters;
extern const struct in6_addr in6addr_linklocal_allv2routers;
struct ipv6_mreq {
 struct in6_addr ipv6mr_multiaddr;
 unsigned int ipv6mr_interface;
};




struct in6_pktinfo {
 struct in6_addr ipi6_addr;
 unsigned int ipi6_ifindex;
};




struct ip6_mtuinfo {
 struct sockaddr_in6 ip6m_addr;
 uint32_t ip6m_mtu;
};








extern int inet_aton(const char *, struct in_addr *);
extern const char *inet_ntop(int, const void *, char *, socklen_t);
typedef struct activity_bitmap {
 uint64_t start;
 uint64_t bitmap[2];
} activity_bitmap_t;

struct timespec
{
 __darwin_time_t tv_sec;
 long tv_nsec;
};
struct timeval
{
 __darwin_time_t tv_sec;
 __darwin_suseconds_t tv_usec;
};


struct timeval64
{
 __int64_t tv_sec;
 __int64_t tv_usec;
};


struct user_timespec
{
 user_time_t tv_sec;
 user_long_t tv_nsec;
};
struct user32_timespec
{
 user32_time_t tv_sec;
 user32_long_t tv_nsec;
};
struct user64_timespec
{
 user64_time_t tv_sec;
 user64_long_t tv_nsec;
};
struct user_timeval
{
 user_time_t tv_sec;
 __int32_t tv_usec;
};
struct user32_timeval
{
 user32_time_t tv_sec;
 __int32_t tv_usec;
};
struct user64_timeval
{
 user64_time_t tv_sec;
 __int32_t tv_usec;
};
struct user32_itimerval
{
 struct user32_timeval it_interval;
 struct user32_timeval it_value;
};
struct user64_itimerval
{
 struct user64_timeval it_interval;
 struct user64_timeval it_value;
};








struct itimerval {
 struct timeval it_interval;
 struct timeval it_value;
};
struct timezone {
 int tz_minuteswest;
 int tz_dsttime;
};
struct clockinfo {
 int hz;
 int tick;
 int tickadj;
 int stathz;
 int profhz;
};






void microtime(struct timeval *tv);
void microtime_with_abstime(struct timeval *tv, uint64_t *abstime);
void microuptime(struct timeval *tv);


void nanotime(struct timespec *ts);
void nanouptime(struct timespec *ts);


void timevaladd(struct timeval *t1, struct timeval *t2);
void timevalsub(struct timeval *t1, struct timeval *t2);
void timevalfix(struct timeval *t1);




struct timeval;
struct sockaddr;
struct sockaddr_dl;
struct kern_event_msg;
struct kev_msg;
struct ifnet_demux_desc;
enum {
 IFNET_FAMILY_ANY = 0,
 IFNET_FAMILY_LOOPBACK = 1,
 IFNET_FAMILY_ETHERNET = 2,
 IFNET_FAMILY_SLIP = 3,
 IFNET_FAMILY_TUN = 4,
 IFNET_FAMILY_VLAN = 5,
 IFNET_FAMILY_PPP = 6,
 IFNET_FAMILY_PVC = 7,
 IFNET_FAMILY_DISC = 8,
 IFNET_FAMILY_MDECAP = 9,
 IFNET_FAMILY_GIF = 10,
 IFNET_FAMILY_FAITH = 11,
 IFNET_FAMILY_STF = 12,
 IFNET_FAMILY_FIREWIRE = 13,
 IFNET_FAMILY_BOND = 14,
 IFNET_FAMILY_CELLULAR = 15
};





typedef u_int32_t ifnet_family_t;
enum {
 BPF_MODE_DISABLED = 0,
 BPF_MODE_INPUT = 1,
 BPF_MODE_OUTPUT = 2,
 BPF_MODE_INPUT_OUTPUT = 3
};




typedef u_int32_t bpf_tap_mode;






typedef u_int32_t protocol_family_t;
enum {
 IFNET_CSUM_IP = 0x00000001,
 IFNET_CSUM_TCP = 0x00000002,
 IFNET_CSUM_UDP = 0x00000004,
 IFNET_CSUM_FRAGMENT = 0x00000008,
 IFNET_IP_FRAGMENT = 0x00000010,
 IFNET_CSUM_TCPIPV6 = 0x00000020,
 IFNET_CSUM_UDPIPV6 = 0x00000040,
 IFNET_IPV6_FRAGMENT = 0x00000080,
 IFNET_VLAN_TAGGING = 0x00010000,
 IFNET_VLAN_MTU = 0x00020000,
 IFNET_MULTIPAGES = 0x00100000,
 IFNET_TSO_IPV4 = 0x00200000,
 IFNET_TSO_IPV6 = 0x00400000,
 IFNET_TX_STATUS = 0x00800000,
 IFNET_HW_TIMESTAMP = 0x01000000,
 IFNET_SW_TIMESTAMP = 0x02000000
};




typedef u_int32_t ifnet_offload_t;
typedef errno_t (*bpf_packet_func)(ifnet_t interface, mbuf_t data);
typedef errno_t (*ifnet_output_func)(ifnet_t interface, mbuf_t data);
typedef errno_t (*ifnet_ioctl_func)(ifnet_t interface, unsigned long cmd,
    void *data);






typedef errno_t (*ifnet_set_bpf_tap)(ifnet_t interface, bpf_tap_mode mode,
    bpf_packet_func callback);
typedef void (*ifnet_detached_func)(ifnet_t interface);
typedef errno_t (*ifnet_demux_func)(ifnet_t interface, mbuf_t packet,
    char *frame_header, protocol_family_t *protocol_family);







typedef void (*ifnet_event_func)(ifnet_t interface, const struct kev_msg *msg);
typedef errno_t (*ifnet_framer_func)(ifnet_t interface, mbuf_t *packet,
 const struct sockaddr *dest, const char *dest_linkaddr,
 const char *frame_type



 );
typedef errno_t (*ifnet_add_proto_func)(ifnet_t interface,
    protocol_family_t protocol_family,
    const struct ifnet_demux_desc *demux_array, u_int32_t demux_count);
typedef errno_t (*ifnet_del_proto_func)(ifnet_t interface,
    protocol_family_t protocol_family);
typedef errno_t (*ifnet_check_multi)(ifnet_t interface,
    const struct sockaddr *mcast);
typedef errno_t (*proto_media_input)(ifnet_t ifp, protocol_family_t protocol,
    mbuf_t packet, char *header);
typedef errno_t (*proto_media_input_v2)(ifnet_t ifp, protocol_family_t protocol,
    mbuf_t packet);
typedef errno_t (*proto_media_preout)(ifnet_t ifp, protocol_family_t protocol,
    mbuf_t *packet, const struct sockaddr *dest, void *route, char *frame_type,
    char *link_layer_dest);
typedef void (*proto_media_event)(ifnet_t ifp, protocol_family_t protocol,
    const struct kev_msg *event);
typedef errno_t (*proto_media_ioctl)(ifnet_t ifp, protocol_family_t protocol,
    unsigned long command, void *argument);
typedef errno_t (*proto_media_detached)(ifnet_t ifp, protocol_family_t protocol);
typedef errno_t (*proto_media_resolve_multi)(ifnet_t ifp,
    const struct sockaddr *proto_addr, struct sockaddr_dl *out_ll,
    size_t ll_len);
typedef errno_t (*proto_media_send_arp)(ifnet_t ifp, u_short arpop,
    const struct sockaddr_dl *sender_hw, const struct sockaddr *sender_proto,
    const struct sockaddr_dl *target_hw, const struct sockaddr *target_proto);
struct ifnet_stat_increment_param {
 u_int32_t packets_in;
 u_int32_t bytes_in;
 u_int32_t errors_in;

 u_int32_t packets_out;
 u_int32_t bytes_out;
 u_int32_t errors_out;

 u_int32_t collisions;
 u_int32_t dropped;
};
struct ifnet_init_params {

 const void *uniqueid;
 u_int32_t uniqueid_len;


 const char *name;
 u_int32_t unit;
 ifnet_family_t family;
 u_int32_t type;
 ifnet_output_func output;
 ifnet_demux_func demux;
 ifnet_add_proto_func add_proto;
 ifnet_del_proto_func del_proto;
 ifnet_check_multi check_multi;
 ifnet_framer_func framer;
 void *softc;
 ifnet_ioctl_func ioctl;
 ifnet_set_bpf_tap set_bpf_tap;
 ifnet_detached_func detach;
 ifnet_event_func event;
 const void *broadcast_addr;
 u_int32_t broadcast_len;
};
struct ifnet_stats_param {
 u_int64_t packets_in;
 u_int64_t bytes_in;
 u_int64_t multicasts_in;
 u_int64_t errors_in;

 u_int64_t packets_out;
 u_int64_t bytes_out;
 u_int64_t multicasts_out;
 u_int64_t errors_out;

 u_int64_t collisions;
 u_int64_t dropped;
 u_int64_t no_protocol;
};
struct ifnet_demux_desc {
 u_int32_t type;
 void *data;
 u_int32_t datalen;
};
struct ifnet_attach_proto_param {
 struct ifnet_demux_desc *demux_array;
 u_int32_t demux_count;

 proto_media_input input;
 proto_media_preout pre_output;
 proto_media_event event;
 proto_media_ioctl ioctl;
 proto_media_detached detached;
 proto_media_resolve_multi resolve;
 proto_media_send_arp send_arp;
};

struct ifnet_attach_proto_param_v2 {
 struct ifnet_demux_desc *demux_array;
 u_int32_t demux_count;

 proto_media_input_v2 input;
 proto_media_preout pre_output;
 proto_media_event event;
 proto_media_ioctl ioctl;
 proto_media_detached detached;
 proto_media_resolve_multi resolve;
 proto_media_send_arp send_arp;
};
extern errno_t ifnet_allocate(const struct ifnet_init_params *init,
    ifnet_t *interface);
extern errno_t ifnet_reference(ifnet_t interface);
extern errno_t ifnet_release(ifnet_t interface);
extern errno_t ifnet_attach(ifnet_t interface,
    const struct sockaddr_dl *ll_addr);
extern errno_t ifnet_detach(ifnet_t interface);
extern errno_t ifnet_interface_family_find(const char *module_string, ifnet_family_t *family_id);
extern void *ifnet_softc(ifnet_t interface);







extern const char *ifnet_name(ifnet_t interface);







extern ifnet_family_t ifnet_family(ifnet_t interface);
extern u_int32_t ifnet_unit(ifnet_t interface);
extern u_int32_t ifnet_index(ifnet_t interface);
extern errno_t ifnet_set_flags(ifnet_t interface, u_int16_t new_flags,
    u_int16_t mask);







extern u_int16_t ifnet_flags(ifnet_t interface);
extern errno_t ifnet_set_capabilities_supported(ifnet_t interface, u_int32_t new_caps,
    u_int32_t mask);







extern u_int32_t ifnet_capabilities_supported(ifnet_t interface);
extern errno_t ifnet_set_capabilities_enabled(ifnet_t interface, u_int32_t new_caps,
    u_int32_t mask);







extern u_int32_t ifnet_capabilities_enabled(ifnet_t interface);
extern errno_t ifnet_set_offload(ifnet_t interface, ifnet_offload_t offload);
extern ifnet_offload_t ifnet_offload(ifnet_t interface);
extern errno_t ifnet_set_tso_mtu(ifnet_t interface, sa_family_t family,
    u_int32_t mtuLen);
extern errno_t ifnet_get_tso_mtu(ifnet_t interface, sa_family_t family,
    u_int32_t *mtuLen);






enum {
 IFNET_WAKE_ON_MAGIC_PACKET = 0x01
};
extern errno_t ifnet_set_wake_flags(ifnet_t interface, u_int32_t properties, u_int32_t mask);







extern u_int32_t ifnet_get_wake_flags(ifnet_t interface);
extern errno_t ifnet_set_link_mib_data(ifnet_t interface, void *mibData,
    u_int32_t mibLen);
extern errno_t ifnet_get_link_mib_data(ifnet_t interface, void *mibData,
    u_int32_t *mibLen);
extern u_int32_t ifnet_get_link_mib_data_length(ifnet_t interface);
extern errno_t ifnet_attach_protocol(ifnet_t interface,
    protocol_family_t protocol_family,
    const struct ifnet_attach_proto_param *proto_details);
extern errno_t ifnet_attach_protocol_v2(ifnet_t interface,
    protocol_family_t protocol_family,
    const struct ifnet_attach_proto_param_v2 *proto_details);
extern errno_t ifnet_detach_protocol(ifnet_t interface,
    protocol_family_t protocol_family);
extern errno_t ifnet_output(ifnet_t interface,
    protocol_family_t protocol_family, mbuf_t packet, void *route,
    const struct sockaddr *dest);
extern errno_t ifnet_output_raw(ifnet_t interface,
    protocol_family_t protocol_family, mbuf_t packet);
extern errno_t ifnet_input(ifnet_t interface, mbuf_t first_packet,
    const struct ifnet_stat_increment_param *stats);
extern errno_t ifnet_ioctl(ifnet_t interface, protocol_family_t protocol,
    unsigned long ioctl_code, void *ioctl_arg);
extern errno_t ifnet_event(ifnet_t interface, struct kern_event_msg *event_ptr);
extern errno_t ifnet_set_mtu(ifnet_t interface, u_int32_t mtu);






extern u_int32_t ifnet_mtu(ifnet_t interface);






extern u_int8_t ifnet_type(ifnet_t interface);
extern errno_t ifnet_set_addrlen(ifnet_t interface, u_int8_t addrlen);






extern u_int8_t ifnet_addrlen(ifnet_t interface);
extern errno_t ifnet_set_hdrlen(ifnet_t interface, u_int8_t hdrlen);






extern u_int8_t ifnet_hdrlen(ifnet_t interface);
extern errno_t ifnet_set_metric(ifnet_t interface, u_int32_t metric);






extern u_int32_t ifnet_metric(ifnet_t interface);
extern errno_t ifnet_set_baudrate(ifnet_t interface, u_int64_t baudrate);






extern u_int64_t ifnet_baudrate(ifnet_t interface);
extern errno_t ifnet_stat_increment(ifnet_t interface,
    const struct ifnet_stat_increment_param *counts);
extern errno_t ifnet_stat_increment_in(ifnet_t interface,
    u_int32_t packets_in, u_int32_t bytes_in, u_int32_t errors_in);
extern errno_t ifnet_stat_increment_out(ifnet_t interface,
u_int32_t packets_out, u_int32_t bytes_out, u_int32_t errors_out);
extern errno_t ifnet_set_stat(ifnet_t interface,
    const struct ifnet_stats_param *stats);







extern errno_t ifnet_stat(ifnet_t interface,
    struct ifnet_stats_param *out_stats);
extern errno_t ifnet_set_promiscuous(ifnet_t interface, int on);







extern errno_t ifnet_touch_lastchange(ifnet_t interface);







extern errno_t ifnet_lastchange(ifnet_t interface, struct timeval *last_change);
extern errno_t ifnet_get_address_list(ifnet_t interface, ifaddr_t **addresses);
extern errno_t ifnet_get_address_list_family(ifnet_t interface,
    ifaddr_t **addresses, sa_family_t family);
extern void ifnet_free_address_list(ifaddr_t *addresses);
extern errno_t ifnet_set_lladdr(ifnet_t interface, const void *lladdr,
    size_t lladdr_len);
extern errno_t ifnet_lladdr_copy_bytes(ifnet_t interface, void *lladdr,
    size_t length);
extern errno_t ifnet_llbroadcast_copy_bytes(ifnet_t interface, void *addr,
    size_t bufferlen, size_t *out_len);
extern errno_t ifnet_resolve_multicast(ifnet_t ifp,
    const struct sockaddr *proto_addr, struct sockaddr *ll_addr, size_t ll_len);
extern errno_t ifnet_add_multicast(ifnet_t interface,
    const struct sockaddr *maddr, ifmultiaddr_t *multicast);
extern errno_t ifnet_remove_multicast(ifmultiaddr_t multicast);
extern errno_t ifnet_get_multicast_list(ifnet_t interface,
    ifmultiaddr_t **addresses);
extern void ifnet_free_multicast_list(ifmultiaddr_t *multicasts);
extern errno_t ifnet_find_by_name(const char *ifname, ifnet_t *interface);
extern errno_t ifnet_list_get(ifnet_family_t family, ifnet_t **interfaces,
    u_int32_t *count);
extern void ifnet_list_free(ifnet_t *interfaces);
extern errno_t ifaddr_reference(ifaddr_t ifaddr);
extern errno_t ifaddr_release(ifaddr_t ifaddr);
extern errno_t ifaddr_address(ifaddr_t ifaddr, struct sockaddr *out_addr,
    u_int32_t addr_size);







extern sa_family_t ifaddr_address_family(ifaddr_t ifaddr);
extern errno_t ifaddr_dstaddress(ifaddr_t ifaddr, struct sockaddr *out_dstaddr,
    u_int32_t dstaddr_size);
extern errno_t ifaddr_netmask(ifaddr_t ifaddr, struct sockaddr *out_netmask,
    u_int32_t netmask_size);
extern ifnet_t ifaddr_ifnet(ifaddr_t ifaddr);
extern ifaddr_t ifaddr_withaddr(const struct sockaddr *address);
extern ifaddr_t ifaddr_withdstaddr(const struct sockaddr *destination);
extern ifaddr_t ifaddr_withnet(const struct sockaddr *net);
extern ifaddr_t ifaddr_withroute(int flags, const struct sockaddr *destination,
    const struct sockaddr *gateway);
extern ifaddr_t ifaddr_findbestforaddr(const struct sockaddr *addr,
    ifnet_t interface);
extern errno_t ifmaddr_reference(ifmultiaddr_t ifmaddr);
extern errno_t ifmaddr_release(ifmultiaddr_t ifmaddr);
extern errno_t ifmaddr_address(ifmultiaddr_t ifmaddr,
    struct sockaddr *out_multicast, u_int32_t addr_size);
extern errno_t ifmaddr_lladdress(ifmultiaddr_t ifmaddr,
    struct sockaddr *out_link_layer_multicast, u_int32_t addr_size);
extern ifnet_t ifmaddr_ifnet(ifmultiaddr_t ifmaddr);
struct net_event_data {
 u_int32_t if_family;
 u_int32_t if_unit;
 char if_name[16];
};



struct timeval32
{
 __int32_t tv_sec;
 __int32_t tv_usec;
};










struct if_data {

 u_char ifi_type;
 u_char ifi_typelen;
 u_char ifi_physical;
 u_char ifi_addrlen;
 u_char ifi_hdrlen;
 u_char ifi_recvquota;
 u_char ifi_xmitquota;
 u_char ifi_unused1;
 u_int32_t ifi_mtu;
 u_int32_t ifi_metric;
 u_int32_t ifi_baudrate;

 u_int32_t ifi_ipackets;
 u_int32_t ifi_ierrors;
 u_int32_t ifi_opackets;
 u_int32_t ifi_oerrors;
 u_int32_t ifi_collisions;
 u_int32_t ifi_ibytes;
 u_int32_t ifi_obytes;
 u_int32_t ifi_imcasts;
 u_int32_t ifi_omcasts;
 u_int32_t ifi_iqdrops;
 u_int32_t ifi_noproto;
 u_int32_t ifi_recvtiming;
 u_int32_t ifi_xmittiming;
 struct timeval32 ifi_lastchange;
 u_int32_t ifi_unused2;
 u_int32_t ifi_hwassist;
 u_int32_t ifi_reserved1;
 u_int32_t ifi_reserved2;
};





struct if_data64 {

 u_char ifi_type;
 u_char ifi_typelen;
 u_char ifi_physical;
 u_char ifi_addrlen;
 u_char ifi_hdrlen;
 u_char ifi_recvquota;
 u_char ifi_xmitquota;
 u_char ifi_unused1;
 u_int32_t ifi_mtu;
 u_int32_t ifi_metric;
 u_int64_t ifi_baudrate;

 u_int64_t ifi_ipackets;
 u_int64_t ifi_ierrors;
 u_int64_t ifi_opackets;
 u_int64_t ifi_oerrors;
 u_int64_t ifi_collisions;
 u_int64_t ifi_ibytes;
 u_int64_t ifi_obytes;
 u_int64_t ifi_imcasts;
 u_int64_t ifi_omcasts;
 u_int64_t ifi_iqdrops;
 u_int64_t ifi_noproto;
 u_int32_t ifi_recvtiming;
 u_int32_t ifi_xmittiming;
 struct timeval32 ifi_lastchange;
};






struct ifqueue {
 void *ifq_head;
 void *ifq_tail;
 int ifq_len;
 int ifq_maxlen;
 int ifq_drops;
};





struct if_clonereq {
 int ifcr_total;
 int ifcr_count;
 char *ifcr_buffer;
};
struct if_msghdr {
 unsigned short ifm_msglen;
 unsigned char ifm_version;
 unsigned char ifm_type;
 int ifm_addrs;
 int ifm_flags;
 unsigned short ifm_index;
 struct if_data ifm_data;
};





struct ifa_msghdr {
 unsigned short ifam_msglen;
 unsigned char ifam_version;
 unsigned char ifam_type;
 int ifam_addrs;
 int ifam_flags;
 unsigned short ifam_index;
 int ifam_metric;
};





struct ifma_msghdr {
 unsigned short ifmam_msglen;
 unsigned char ifmam_version;
 unsigned char ifmam_type;
 int ifmam_addrs;
 int ifmam_flags;
 unsigned short ifmam_index;
};





struct if_msghdr2 {
 u_short ifm_msglen;
 u_char ifm_version;
 u_char ifm_type;
 int ifm_addrs;
 int ifm_flags;
 u_short ifm_index;
 int ifm_snd_len;
 int ifm_snd_maxlen;
 int ifm_snd_drops;
 int ifm_timer;
 struct if_data64 ifm_data;
};





struct ifma_msghdr2 {
 u_short ifmam_msglen;
 u_char ifmam_version;
 u_char ifmam_type;
 int ifmam_addrs;
 int ifmam_flags;
 u_short ifmam_index;
 int32_t ifmam_refcount;
};






struct ifdevmtu {
 int ifdm_current;
 int ifdm_min;
 int ifdm_max;
};

struct ifkpi {
 unsigned int ifk_module_id;
 unsigned int ifk_type;
 union {
  void *ifk_ptr;
  int ifk_value;
  u_int64_t ifk_ptr64;
 } ifk_data;
};












struct ifreq {



 char ifr_name[16];
 union {
  struct sockaddr ifru_addr;
  struct sockaddr ifru_dstaddr;
  struct sockaddr ifru_broadaddr;
  short ifru_flags;
  int ifru_metric;
  int ifru_mtu;
  int ifru_phys;
  int ifru_media;
  int ifru_intval;
  caddr_t ifru_data;
  struct ifdevmtu ifru_devmtu;
  struct ifkpi ifru_kpi;
  u_int32_t ifru_wake_flags;
  u_int32_t ifru_route_refcnt;
  int ifru_cap[2];
  u_int32_t ifru_functional_type;
 } ifr_ifru;
};






struct ifaliasreq {
 char ifra_name[16];
 struct sockaddr ifra_addr;
 struct sockaddr ifra_broadaddr;
 struct sockaddr ifra_mask;
};

struct rslvmulti_req {
 struct sockaddr *sa;
 struct sockaddr **llsa;
};




struct ifdrv {
 char ifd_name[16];
 unsigned long ifd_cmd;
 size_t ifd_len;
 void *ifd_data;
};
struct ifstat {
 char ifs_name[16];
 char ascii[800 + 1];
};






struct kev_dl_proto_data {
 struct net_event_data link_data;
 u_int32_t proto_family;
 u_int32_t proto_remaining_count;
};








struct necp_packet_header {
    u_int8_t packet_type;
 u_int8_t flags;
    u_int32_t message_id;
};
struct necp_policy_condition_tc_range {
 u_int32_t start_tc;
 u_int32_t end_tc;
} __attribute__((__packed__));

struct necp_policy_condition_addr {
 u_int8_t prefix;
 union {
  struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
 } address;
} __attribute__((__packed__));

struct necp_policy_condition_addr_range {
 union {
  struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
 } start_address;
 union {
  struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
 } end_address;
} __attribute__((__packed__));
typedef u_int32_t necp_policy_id;
typedef u_int32_t necp_policy_order;
typedef u_int32_t necp_session_priority;

typedef u_int32_t necp_kernel_policy_result;
typedef u_int32_t necp_kernel_policy_filter;

typedef union {
 u_int tunnel_interface_index;
 u_int scoped_interface_index;
 u_int32_t flow_divert_control_unit;
 u_int32_t filter_control_unit;
} necp_kernel_policy_routing_result_parameter;





struct necp_aggregate_result {
 necp_kernel_policy_result routing_result;
 necp_kernel_policy_routing_result_parameter routing_result_parameter;
 necp_kernel_policy_filter filter_control_unit;
 necp_kernel_policy_result service_action;
 uuid_t service_uuid;
 u_int32_t service_flags;
 u_int32_t service_data;
 u_int routed_interface_index;
 u_int32_t policy_id;
 uuid_t netagents[8];
 u_int32_t netagent_flags[8];
 u_int8_t mss_recommended;
};






struct necp_stat_counts
{

 u_int64_t necp_stat_rxpackets __attribute__((aligned(8)));
 u_int64_t necp_stat_rxbytes __attribute__((aligned(8)));
 u_int64_t necp_stat_txpackets __attribute__((aligned(8)));
 u_int64_t necp_stat_txbytes __attribute__((aligned(8)));

 u_int32_t necp_stat_rxduplicatebytes;
 u_int32_t necp_stat_rxoutoforderbytes;
 u_int32_t necp_stat_txretransmit;

 u_int32_t necp_stat_connectattempts;
 u_int32_t necp_stat_connectsuccesses;

 u_int32_t necp_stat_min_rtt;
 u_int32_t necp_stat_avg_rtt;
 u_int32_t necp_stat_var_rtt;

};







struct necp_basic_metadata
{
 u_int32_t rcvbufsize;
 u_int32_t rcvbufused;
};

struct necp_tcp_probe_status {
 unsigned int probe_activated : 1;
 unsigned int write_probe_failed : 1;
 unsigned int read_probe_failed : 1;
 unsigned int conn_probe_failed : 1;
};

struct necp_extra_tcp_metadata
{
 struct necp_tcp_probe_status probestatus;

 u_int32_t sndbufsize;
 u_int32_t sndbufused;
 u_int32_t txunacked;
 u_int32_t txwindow;
 u_int32_t txcwindow;
 u_int32_t flags;
 u_int32_t flags1;
 u_int32_t traffic_mgt_flags;
 u_int32_t cc_alg_index;
 u_int32_t state;
 activity_bitmap_t activity_bitmap;
};

struct necp_stats_hdr {
 u_int32_t necp_stats_type __attribute__((aligned(8)));
 u_int32_t necp_stats_ver;
 u_int64_t __necp_stats_reserved;
};
struct necp_tcp_stats {
 struct necp_stats_hdr necp_tcp_hdr;
 struct necp_stat_counts necp_tcp_counts;
 struct necp_basic_metadata necp_tcp_basic;
 struct necp_extra_tcp_metadata necp_tcp_extra;
};

struct necp_udp_stats {
 struct necp_stats_hdr necp_udp_hdr;
 struct necp_stat_counts necp_udp_counts;
 struct necp_basic_metadata necp_udp_basic;
};

typedef struct necp_all_stats {
 union {
  struct necp_tcp_stats tcp_stats;
  struct necp_udp_stats udp_stats;
 } all_stats_u;
} necp_all_stats;



struct necp_stats_bufreq {
 u_int32_t necp_stats_bufreq_id __attribute__((aligned(8)));
 u_int32_t necp_stats_bufreq_type;
 u_int32_t necp_stats_bufreq_ver;
 u_int32_t necp_stats_bufreq_size;
 union {
  void *necp_stats_bufreq_addr;
  mach_vm_address_t necp_stats_bufreq_uaddr;
 };
};
typedef struct necp_tcp_ecn_cache {
 u_int8_t necp_tcp_ecn_heuristics_success:1;
 u_int8_t necp_tcp_ecn_heuristics_loss:1;
 u_int8_t necp_tcp_ecn_heuristics_drop_rst:1;
 u_int8_t necp_tcp_ecn_heuristics_drop_rxmt:1;
 u_int8_t necp_tcp_ecn_heuristics_aggressive:1;
 u_int8_t necp_tcp_ecn_heuristics_syn_rst:1;
} necp_tcp_ecn_cache;


typedef struct necp_tcp_tfo_cache {
 u_int8_t necp_tcp_tfo_cookie[16];
 u_int8_t necp_tcp_tfo_cookie_len;
 u_int8_t necp_tcp_tfo_heuristics_success:1;
 u_int8_t necp_tcp_tfo_heuristics_loss:1;
 u_int8_t necp_tcp_tfo_heuristics_middlebox:1;
 u_int8_t necp_tcp_tfo_heuristics_success_req:1;
 u_int8_t necp_tcp_tfo_heuristics_loss_req:1;
 u_int8_t necp_tcp_tfo_heuristics_rst_data:1;
 u_int8_t necp_tcp_tfo_heuristics_rst_req:1;
} necp_tcp_tfo_cache;







typedef struct necp_cache_buffer {
 u_int8_t necp_cache_buf_type;
 u_int8_t necp_cache_buf_ver;
 u_int32_t necp_cache_buf_size;
 mach_vm_address_t necp_cache_buf_addr;
} necp_cache_buffer;
struct necp_interface_signature {
 u_int8_t signature[IFNET_SIGNATURELEN];
 u_int8_t signature_len;
};

struct necp_interface_details {
 char name[IFXNAMSIZ];
 u_int32_t index;
 u_int32_t generation;
 u_int32_t functional_type;
 u_int32_t delegate_index;
 u_int32_t flags;
 u_int32_t mtu;
 struct necp_interface_signature ipv4_signature;
 struct necp_interface_signature ipv6_signature;
};





struct necp_client_parameter_netagent_type {
 char netagent_domain[32];
 char netagent_type[32];
};

struct necp_client_result_netagent {
 u_int32_t generation;
 uuid_t netagent_uuid;
};

struct necp_client_result_interface {
 u_int32_t generation;
 u_int32_t index;
};

struct necp_client_endpoint {
 union {
  struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  struct {
   u_int8_t endpoint_length;
   u_int8_t endpoint_family;
   u_int16_t endpoint_port;
   u_int32_t endpoint_type;
   char endpoint_data[0];
  } endpoint;
 } u;
};

struct necp_client_list {
 u_int32_t client_count;
 uuid_t clients[0];
};

struct kev_necp_policies_changed_data {
 u_int32_t changed_count;
};

struct necp_agent_use_parameters {
 uuid_t agent_uuid;
 uint64_t out_use_count;
};

struct necp_client_flow_protoctl_event {
 uint32_t protoctl_event_code;
 uint32_t protoctl_event_val;

 uint32_t protoctl_event_tcp_seq_num;
};





struct necp_client_observer_update {
 u_int32_t update_type;
 u_int8_t tlv_buffer[0];
};
extern int necp_match_policy(const uint8_t *parameters, size_t parameters_size, struct necp_aggregate_result *returned_result);

extern int necp_open(int flags);

extern int necp_client_action(int necp_fd, uint32_t action, uuid_t client_id,
         size_t client_id_len, uint8_t *buffer, size_t buffer_size);

extern int necp_session_open(int flags);

extern int necp_session_action(int necp_fd, uint32_t action,
          uint8_t *in_buffer, size_t in_buffer_length,
          uint8_t *out_buffer, size_t out_buffer_length);
