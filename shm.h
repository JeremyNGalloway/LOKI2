/*
 * LOKI
 *
 * shm header file
 *
 *  1996/7 Guild Corporation Productions    [daemon9]
 */
 

#define SHM_KEY     242                 /* Shared memory key            */
#define SEM_KEY     424                 /* Semaphore key                */
#define SHM_PRM     S_IRUSR|S_IWUSR     /* Shared Memory Permissions    */
#define SET_SIZE    1

void prep_shm();                        /* prepare shared mem segment   */
void locks();                           /* lock shared memory           */
void ulocks();                          /* unlock shared memory         */
void dump_shm();                        /* release shared memory        */
