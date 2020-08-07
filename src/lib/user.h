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
        User(unsigned int keysize);
        ~User(void);
        
        std::pair<BIGNUM *, BIGNUM *> UserTD(const unsigned char *, unsigned int);
        char * FullUserTD(const std::vector<std::pair<BIGNUM *, BIGNUM *> > *);
		
		BIGNUM * UserDec(const std::pair<BIGNUM *, BIGNUM *> e);
		std::pair<BIGNUM *, BIGNUM *> ContentProviderEnc(const unsigned char *, unsigned int);
		
        void setSalt(const BIGNUM *);
        void setUserKey(const BIGNUM *);
        void setNumberG(const BIGNUM *);
        void setPrimeQ(const BIGNUM *);
        
        unsigned int keysize;
};
#endif /* __cplusplus */

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
User * libprotector_User_new(unsigned int keysize);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
{
    void libprotector_User_setUserKey(User * u, const char * user_key);
    void libprotector_User_setNumberG(User * u, const char * number_g);
    void libprotector_User_setPrimeQ(User * u, const char * prime_q);
    void libprotector_User_setSalt(User * u, const char * salt_key);
    void libprotector_User_UserTD(User * u, const unsigned char * component, unsigned int size_component, char *& p1, char *& p2);
    void libprotector_User_ContentTD(User * u, const unsigned char * block, const unsigned int block_size, char *& p1, char *& p2);
    void libprotector_User_ClientDec(User * u, const char * component1, const char * component2, char *& p1);
}

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
