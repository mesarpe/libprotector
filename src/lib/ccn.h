#ifndef CCN_H
#define CCN_H

#include <openssl/bn.h>
#include <openssl/bio.h>

#ifdef __cplusplus
    #include <string>
    #include <cstring>
    #include <utility>
    #include <vector>
#endif /* __cplusplus */

#include <openssl/bio.h>
#include <openssl/evp.h>

#ifdef __cplusplus
    class CCN{
        BIGNUM * numberX_2;
        BIGNUM * primeQ;
		BIGNUM * numberG;
        

        public:
            CCN(unsigned int keysize);
            ~CCN(void);
            BIGNUM * CCNTD(const std::pair<BIGNUM *, BIGNUM *>);
            char * FullCCNTD(const std::vector<std::pair<BIGNUM *, BIGNUM *> > *);
            char * FullCCNTD(const char *);
			
			std::pair<BIGNUM *, BIGNUM *> CCNPreDec(const std::pair<BIGNUM *, BIGNUM *>);
			std::pair<BIGNUM *, BIGNUM *> ContentProviderReEnc(const std::pair<BIGNUM *, BIGNUM *>);

            bool MatchTDs(const BIGNUM *, const BIGNUM *);
            void setServerKey(const BIGNUM *);
            void setPrimeQ(const BIGNUM *);
			void setNumberG(const BIGNUM *);
			
			unsigned int keysize;
    };
#endif /* __cplusplus */

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * ReEncryptUserTD(const char * user_trapdoor, const BIGNUM * primeP,  const BIGNUM * serverKey);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * libprotector_SimpleReEncryptUserTD(const char * user_trapdoor);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * libprotector_ReEncryptUserContent(const char * user_encr_content, const unsigned int user_encr_len);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * libprotector_ReEncryptUserContentNoNetwork(const char * user_encr_content, const unsigned int user_encr_len, const BIGNUM * serverKey, const BIGNUM * router_primeQ);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * libprotector_ReEncryptAndSplitUserContent(const char * user_encr_content, const unsigned int user_encr_len);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * libprotector_DecryptContent(const char * reencrypted_content);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * libprotector_DecryptAndSplitContent(const char * reencrypted_content);



#endif
