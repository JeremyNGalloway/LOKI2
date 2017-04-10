/*
 * LOKI
 *
 * client_db header file
 *
 *  1996/7 Guild Corporation Productions    [daemon9]
 */
 

/*
 *  Client info list.  
 *  MAX_CLIENT of these will be kept in a server-side array
 */

struct client_list
{
#ifdef  STRONG_CRYPTO
    u_char key[BF_KEYSIZE];             /* unset bf key                     */
    u_short ivec_salt;                  /* the IV salter                    */
#endif
    u_short client_id;                  /* client loki_id                   */
    u_long client_ip;                   /* client IP address                */
    time_t  touchtime;                  /* last time entry was hit          */
    u_long packets_sent;                /* Packets sent to this client      */
    u_long bytes_sent;                  /* Bytes sent to this client        */
    u_int hits;                         /* Number of queries from client    */
#ifdef  PTY
    int pty_fd;                         /* Master PTY file descriptor       */
#endif
};

#define IS_GOOD_CLIENT(ldg)\
\
(c_id           == client[i].client_id   &&  \
 ldg.iph.ip_src == client[i].client_ip)  >   \
                             (0) ? (1) : (0) \

void update_client(int, int, u_long);   /* Update a client entry            */
                                        /* client info into supplied buffer */
int stat_client(int, u_char *, int, time_t);
int add_client(u_char *);               /* add a client entry               */
int locate_client(int);                 /* find a client entry              */
void age_client(void);                  /* age a client from the list       */
u_short update_client_salt(int);        /* update and return salt           */
u_long check_client_ip(int, u_short *); /* return ip and id of target       */
