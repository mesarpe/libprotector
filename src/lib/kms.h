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
		
		inline int getKeysize(void) { return this->nr_bits; };
    private:
		    // These tables store the user and server keys
		    MyHashTable * table_user_keys;
		    MyHashTable * table_server_keys;
        };
#endif /* __cplusplus */

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
KMS * libprotector_KMS_new();

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
{
    void libprotector_KMS_destroy(KMS * kms);
    int libprotector_KMS_InitKMS(KMS * kms, int nr_bits);
    int libprotector_KMS_addUser(KMS * kms );
    char * libprotector_KMS_getProxyKey(KMS * kms, unsigned int user_id);
    char * libprotector_KMS_getClientKey(KMS * kms, unsigned int user_id);
    char * libprotector_KMS_getPrimeQ(KMS * kms);
}

#endif
