#include <openssl/bn.h>
#include <string.h>
#include <iostream>

#include "../lib/kms.h"

int main(int argc, char** argv)
{
    unsigned int N = std::stoul(argv[1], nullptr, 0);

    KMS * kms = new KMS();
    kms->InitKMS(std::stoul(argv[2], nullptr, 0));
    
    for(unsigned int i=0; i<N; i++)
    {
        kms->addUser();
        
        printf("%s\n", kms->getServerKey(i));
    }
    
    delete kms;
    
    /*std::string * msg2 = new std::string("serverK:0");
    char * res = retrieveKeyFromServer(msg2->c_str());
    printf("Retrieved key: %s\n", res);
    free(res);
    delete msg2;*/
    return 0;
}
