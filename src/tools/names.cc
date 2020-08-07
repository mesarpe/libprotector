#include <openssl/bn.h>
#include <string.h>
#include <iostream>

#include "../lib/kms.h"
#include "../lib/user.h"

int main(int argc, char** argv)
{
    printf("Call ./names [QUANTITY] [KEYSIZE] \n");
    unsigned int N = std::stoul(argv[1], nullptr, 0);
    unsigned long keysize = std::stoul(argv[2], nullptr, 0);

    /*KMS * kms = new KMS();
    kms->InitKMS(keysize);
    
    for(unsigned int i=0; i<N; i++)
    {
        kms->addUser();
        
        printf("%s\n", kms->getServerKey(i));
        
        User * u = new User(keysize);
        u->setPrimeQ(kms->getPrimeQ());
        u->setUserKey(kms->getUserKey(i))
        //u.setNumberG("2")
        delete u;
    }
    
    delete kms;*/
    
    KMS * kms = libprotector_KMS_new();
    libprotector_KMS_InitKMS(kms, keysize);
    
    for(unsigned int i=0; i<N; i++)
    {
        libprotector_KMS_addUser(kms);
        char * pk = libprotector_KMS_getProxyKey(kms, i);
        char * uk = libprotector_KMS_getClientKey(kms, i);
        char * prime_q = libprotector_KMS_getPrimeQ(kms);
        
        User * u = libprotector_User_new(keysize);
        libprotector_User_setNumberG(u, "2");
        libprotector_User_setUserKey(u, uk);
        libprotector_User_setPrimeQ(u, prime_q);
        char * a;
        char * b;
        a = (char*)malloc(sizeof(char)*2560);
        b = (char*)malloc(sizeof(char)*2560);
        libprotector_User_ContentTD(u, "hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello", 241, a, b);
        printf("%s %s\n", a, b);
        
        char * c = (char*)malloc(sizeof(char)*256);
        libprotector_User_ClientDec(u, a, b, c);
        
        printf("Decr=%s\n", c);
        delete u;
        //        char * EncryptUserName(const char * original_content_name);
    }

    libprotector_KMS_destroy(kms);
/*    int libprotector_KMS_InitKMS(KMS * kms, int nr_bits);
    int libprotector_KMS_addUser(KMS * kms );
    char * libprotector_KMS_getProxyKey(KMS * kms, unsigned int user_id);
    char * libprotector_KMS_getClientKey(KMS * kms, unsigned int user_id);
    char * libprotector_KMS_getPrimeQ(KMS * kms);*/
    
    
    
    
    
    /*std::string * msg2 = new std::string("serverK:0");
    char * res = retrieveKeyFromServer(msg2->c_str());
    printf("Retrieved key: %s\n", res);
    free(res);
    delete msg2;*/
    return 0;
}
