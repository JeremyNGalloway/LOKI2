/*
 * LOKI2
 *
 * [ client_db.c ]
 *
 *  1996/7 Guild Corporation Worldwide      [daemon9]
 */


#include "loki.h"
#include "shm.h"
#include "client_db.h"

extern struct loki rdg;
extern int verbose;
extern int destroy_shm;
extern struct client_list *client;
extern u_short c_id;

#ifdef  STRONG_CRYPTO
extern short ivec_salt;
extern u_char user_key[BF_KEYSIZE];
#endif
#ifdef  PTY
extern int mfd;
#endif
       
/*
 *  The server maintains an array of active client information.  This
 *  function simply steps through the structure array and attempts to add
 *  an entry.
 */

int add_client(u_char *key)
{
    int i = 0, emptyslot = -1;                                    
#ifdef  PTY
    char p_name[BUFSIZE] = {0};
#endif

    locks();
    for (; i < MAX_CLIENT; i++)
    {
        if (IS_GOOD_CLIENT(rdg))
        {                               /* Check for duplicate entries 
                                         * (which are to be expected when
                                         * not using STRONG_CRYPTO)
                                         */
#ifdef STRONG_CRYPTO
            if (verbose) fprintf(stderr, S_MSG_DUP);
#endif
            emptyslot = i;
            break;
        }                               /* tag the first empty slot found */
        if ((!(client[i].client_id))) emptyslot = i;
    }
    if (emptyslot == -1)
    {                                   /* No empty array slots */
        if (verbose) fprintf(stderr, "\nlokid: Client database full");
        ulocks();
        return (NNOK);
    }
                                        /* Initialize array with client info */
    client[emptyslot].touchtime         = time((time_t *)NULL);
    if (emptyslot != i){
        client[emptyslot].client_id     = c_id;
        client[emptyslot].client_ip     = rdg.iph.ip_src;
        client[emptyslot].packets_sent  = 0;
        client[emptyslot].bytes_sent    = 0;
        client[emptyslot].hits          = 0;
#ifdef  PTY
        client[emptyslot].pty_fd        = 0;
#endif
    }
#ifdef  STRONG_CRYPTO
                                        /* copy unset bf key and set salt */
    bcopy(key, client[emptyslot].key, BF_KEYSIZE);
    client[emptyslot].ivec_salt         = 0;
#endif
    ulocks();
    return (emptyslot);
}                


/*
 *  Look for a client entry in the client database.  Either copy the clients
 *  key into user_key and update timestamp, or clear the array entry,
 *  depending on the disposition of the call.
 */

int locate_client(int disposition)
{
    int i = 0;

    locks();
    for (; i < MAX_CLIENT; i++)
    {
        if (IS_GOOD_CLIENT(rdg))
        {
            if (disposition == FIND)    /* update timestamp */
            {
                client[i].touchtime = time((time_t *)NULL);
#ifdef STRONG_CRYPTO
                                        /* Grab the key */
                bcopy(client[i].key, user_key, BF_KEYSIZE);
#endif
            }  
                                        /* Remove entry */
            else if (disposition == DESTROY)
                bzero(&client[i], sizeof(client[i]));
            ulocks();
            return (i);
        }
    }
    ulocks();                           /* Didn't find the client */
    return (NNOK);
}


/*
 *  Fill a string with current stats about a particular client.
 */

int stat_client(int entry, u_char *buf, int prot, time_t uptime)
{

    int n = 0;
    time_t now = 0;
    struct protoent *proto = 0;  
                                        /* locate_client didn't find an 
                                         * entry
                                         */
    if (entry == NNOK)
    {
 fprintf(stderr, "DEBUG: stat_client nono\n");
        return (NOK);
    }
    n = sprintf(buf, "\nlokid version:\t\t%s\n", VERSION);
    n += sprintf(&buf[n], "remote interface:\t%s\n", host_lookup(rdg.iph.ip_dst));

    proto = getprotobynumber(prot);
    n += sprintf(&buf[n], "active transport:\t%s\n", proto -> p_name);
    n += sprintf(&buf[n], "active cryptography:\t%s\n", CRYPTO_TYPE);
    time(&now);
    n += sprintf(&buf[n], "server uptime:\t\t%.02f minutes\n", difftime(now, uptime) / 0x3c);
                                                               
    locks();
    n += sprintf(&buf[n], "client ID:\t\t%d\n",      client[entry].client_id);
    n += sprintf(&buf[n], "packets written:\t%ld\n", client[entry].packets_sent);
    n += sprintf(&buf[n], "bytes written:\t\t%ld\n", client[entry].bytes_sent);
    n += sprintf(&buf[n], "requests:\t\t%d\n",       client[entry].hits);
    ulocks();
    
    return (n);
}

/*
 *  Unsets alarm timer, then calls age_client, then resets signal handler
 *  and alarm timer.
 */

void client_expiry_check(){

    alarm(0);
    age_client();
                                            /* re-establish signal handler */
    if (signal(SIGALRM, client_expiry_check) == SIG_ERR)
        err_exit(1, 1, verbose, "[fatal] cannot catch SIGALRM");

    alarm(KEY_TIMER);
}
     

/*
 *  This function is called every KEY_TIMER interval to sweep through the 
 *  client list.  It zeros any entrys it finds that have not been accessed
 *  in KEY_TIMER seconds.  This gives us a way to free up entries from clients 
 *  which may have crashed or lost their QUIT_C packet in transit.
 */

void age_client()
{

    time_t timestamp = 0;
    int i = 0;

    time(&timestamp); 
    locks();
    for (; i < MAX_CLIENT; i++)
    {
        if (client[i].client_id)
        {
            if (difftime(timestamp, client[i].touchtime) > KEY_TIMER)
            {
                if (verbose) fprintf(stderr, "\nlokid: inactive client <%d> expired from list [%d]\n", client[i].client_id, i);
                bzero(&client[i], sizeof(client[i]));
#ifdef STRONG_CRYPTO
                ivec_salt = 0;
#endif
            }
        }
    }
    ulocks();
}


/*
 *  Update the statistics for client.
 */

void update_client(int entry, int pcount, u_long bcount)
{
    locks();
    client[entry].touchtime      = time((time_t *)NULL);
    client[entry].packets_sent  += pcount; 
    client[entry].bytes_sent    += bcount;
    client[entry].hits          ++;
    ulocks();
}


/*
 *  Returns the IP address and ID of the targeted entry
 */

u_long check_client_ip(int entry, u_short *id)
{
    u_long ip = 0;

    locks();
    if ((*id = (client[entry].client_id))) ip = client[entry].client_ip;
    ulocks();
    
    return (ip);
}

#ifdef STRONG_CRYPTO

/*
 *  Update and return the IV salt for the client
 */

u_short update_client_salt(int entry)
{

    u_short salt = 0;

    locks();
    salt = ++client[entry].ivec_salt;
    ulocks();

    return (salt);
}    

#endif  /* STRONG_CRYPTO */


/* EOF */
