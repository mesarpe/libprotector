#ifndef USER_H
#define USER_H

#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/bio.h>

#ifdef __cplusplus
    #include <string>
    #include <cstring>
    #include <utility>
    #include <vector>
#endif

#include <openssl/bio.h>
#include <openssl/evp.h>

#ifdef __cplusplus
class User{
    BIGNUM * numberX_1 = NULL;
    BIGNUM * numberS = NULL;
    BIGNUM * numberG = NULL;
    BIGNUM * primeQ = NULL;

    public:
        User(void);
        ~User(void);
        
        std::pair<BIGNUM *, BIGNUM *> UserTD(const unsigned char *, unsigned int);
        char * FullUserTD(const std::vector<std::pair<BIGNUM *, BIGNUM *> > *);
		
		BIGNUM * UserDec(const std::pair<BIGNUM *, BIGNUM *> e);
		std::pair<BIGNUM *, BIGNUM *> ContentProviderEnc(const unsigned char *, unsigned int);
		
        void setSalt(const BIGNUM *);
        void setUserKey(const BIGNUM *);
        void setNumberG(const BIGNUM *);
        void setPrimeQ(const BIGNUM *);
};
#endif /* __cplusplus */

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * EncryptUserName(const char * original_content_name);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * libprotector_EncryptUserContent(const unsigned char * original_content, const unsigned int content_len);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * EncryptUserContentNoNetwork(const unsigned char * original_content, const unsigned int content_len, const BIGNUM * primeQ, const BIGNUM * userKey);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
unsigned char * libprotector_ReDecryptContent(const char * encrypted_content);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
unsigned char * libprotector_ReDecryptAndSplitContent(const char * encrypted_content);

#endif
