#ifndef KMS_H
#define KMS_H

#include <openssl/bn.h>
#include <openssl/bio.h>

#ifdef __cplusplus
    #include <string>
    #include <cstring>
    #include <utility>
#endif /* __cplusplus */

#include <openssl/evp.h>
#include "hashtable.h"

#ifdef __cplusplus
    class KMS{
	    BIGNUM * primeP = NULL;
        BIGNUM * primeQ;
        BIGNUM * numberG = NULL;

        BIGNUM * numberX = NULL;
        BIGNUM * secretH = NULL;

        BIGNUM * numberS = NULL;

        int nr_bits;
	
      public:
        KMS(void);
        ~KMS(void);
        int InitKMS(int);
        std::pair<BIGNUM *, BIGNUM *> keyGenKMS(void);
		unsigned int addUser(void);
        BIGNUM * getPrimeQ(void);
		char * getServerKey(unsigned int index);
		char * getUserKey(unsigned int index);
		
private:
		// These tables store the user and server keys
		MyHashTable * table_user_keys;
		MyHashTable * table_server_keys;
    };
#endif /* __cplusplus */

#endif
