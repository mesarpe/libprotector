#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../src/lib/user.h"
#include "../src/lib/ccn.h"
#include "../src/lib/kms.h"

#include "../src/lib/utils.h"

TEST_CASE("Repeat all the steps to encrypt and decrypt content"){
    // THIS TEST REQUIRES THAT the kms_server is running
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * 80);
	message_to_send[0] = 'H';
	message_to_send[1] = 'O';
	message_to_send[2] = 'L';
	message_to_send[3] = 'A';
	message_to_send[4] = '\0';

    std::vector<std::pair <unsigned char*, unsigned int> > p;
    p = Base64Splitter(message_to_send, strlen((char *) message_to_send), 32);
    
    /* The script repeats */
    char * example1 = NULL;
    char * example2 = NULL;
    char * example3 = NULL;
    unsigned char * example4 = NULL;
    std::vector< std::pair <unsigned char*, unsigned int> > rebuild_vector;
    unsigned int rebuild_size = 0;
    for(unsigned int j=0; j<p.size(); j++)
    {
	    example1 = EncryptUserContent(p[j].first, p[j].second);
	    printf("EncryptUserContent: %s\n", example1);
	    
        example2 = libprotector_ReEncryptUserContent(example1, strlen(example1));
        printf("ReEncryptUserContent: %s\n", example2);
        
        example3 = libprotector_DecryptContent(example2);
        printf("Pre-DecryptUserContent: %s\n", example3);
        
        
	    example4 = ReDecryptContent(example3);
	    
	    //CHECK_EQ(example4, "HOLA");

        //rebuild_vector.push_back(std::make_pair(example4, strlen(example4) + 1));
        //rebuild_size += strlen(example4);

        free(example4);
        free(example3);
        free(example2);
        free(example1);
        
        free(p[j].first);
    }
    
    free(message_to_send);
}
