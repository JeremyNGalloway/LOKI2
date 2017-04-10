# Makefile for LOKI2 Sun Jul 27 21:29:28 PDT 1997 
# route (c) 1997 Guild Corporation, Worldwide


######
#   Choose a cryptography type
#

#CRYPTO_TYPE 		=   WEAK_CRYPTO         # XOR
CRYPTO_TYPE 		=   NO_CRYPTO           # Plaintext
#CRYPTO_TYPE 		=   STRONG_CRYPTO       # Blowfish and DH


######
#   If you want STRONG_CRYPTO, uncomment the following (and make sure you have
#   SSLeay)

#LIB_CRYPTO_PATH 	=   /usr/local/ssl/lib/
#CLIB             	=   -L$(LIB_CRYPTO_PATH) -lcrypto
#MD5_OBJ          	=   md5/md5c.o


######
#   Choose a child process handler type
#

SPAWN_TYPE       	=   POPEN 
#SPAWN_TYPE      	=   PTY


######
#   Addedum
#

NET3                    =   -DNET3
SEND_PAUSE       	=   SEND_PAUSE=100 
DEBUG                   =   -DDEBUG
#----------------------------------------------------------------------------#


i_hear_a_voice_from_the_back_of_the_room:
	@echo 
	@echo "LOKI2 Makefile"
	@echo "Edit the Makefile and then invoke with one of the following:"
	@echo 
	@echo "linux openbsd freebsd solaris    clean"
	@echo 
	@echo "See Phrack Magazine issue 51 article 7 for verbose instructions"
	@echo 

linux:
	@make OS=-DLINUX CRYPTO_TYPE=-D$(CRYPTO_TYPE)                       \
	SPAWN_TYPE=-D$(SPAWN_TYPE) SEND_PAUSE=-D$(SEND_PAUSE)               \
	FAST_CHECK=-Dx86_FAST_CHECK IP_LEN= all

openbsd:
	@make OS=-DBSD4 CRYPTO_TYPE=-D$(CRYPTO_TYPE)                        \
	SPAWN_TYPE=-D$(SPAWN_TYPE) SEND_PAUSE=-D$(SEND_PAUSE)               \
	FAST_CHECK=-Dx86_FAST_CHECK IP_LEN= all

freebsd:
	@make OS=-DBSD4 CRYPTO_TYPE=-D$(CRYPTO_TYPE)                        \
	SPAWN_TYPE=-D$(SPAWN_TYPE) SEND_PAUSE=-D$(SEND_PAUSE)               \
	FAST_CHECK=-Dx86_FAST_CHECK IP_LEN=-DBROKEN_IP_LEN all

solaris:
	@make OS=-DSOLARIS CRYPTO_TYPE=-D$(CRYPTO_TYPE)                     \
	SPAWN_TYPE=-D$(SPAWN_TYPE) SEND_PAUSE=-D$(SEND_PAUSE)               \
	LIBS+=-lsocket LIBS+=-lnsl IP_LEN= all

CFLAGS		= -Wall -O6 -finline-functions -funroll-all-loops $(OS)     \
		$(CRYPTO_TYPE) $(SPAWN_TYPE) $(SEND_PAUSE) $(FAST_CHECK)    \
		$(EXTRAS) $(IP_LEN) $(DEBUG) $(NET3)

CC		=   gcc
C_OBJS	        =   surplus.o crypt.o
S_OBJS	        =   client_db.o shm.o surplus.o crypt.o pty.o


.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

all:	$(MD5_OBJ) loki

md5obj: md5/md5c.c
	@( cd md5; make )

loki:	$(C_OBJS) loki.o $(S_OBJS) lokid.o
	$(CC) $(CFLAGS) $(C_OBJS) $(MD5_OBJ) loki.c -o loki $(CLIB) $(LIBS)
	$(CC) $(CFLAGS) $(S_OBJS) $(MD5_OBJ) lokid.c -o lokid $(CLIB) $(LIBS)
	@(strip loki lokid)

clean:
	@( rm -fr *.o loki lokid )
	@( cd md5; make clean )

dist:	clean
	@( cd .. ; tar cvf loki2.tar Loki/ ; gzip loki2.tar )
