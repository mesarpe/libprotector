#include <openssl/bn.h>
#include <string.h>

#include "user.h"
#include "ccn.h"

#include "utils.h"


int main(void)
{
    std::string content_name = std::string("/hola/mundo");

    char * encrypted_content_name = EncryptUserName(content_name.c_str());

    char * reencrypted_content_name = libprotector_SimpleReEncryptUserTD(encrypted_content_name);

    free(reencrypted_content_name);

    free(encrypted_content_name);
	
	/* BEGIN USER WRAPPER */
	
	char * res_getUserK = retrieveKeyFromServer("userK:0");
    char * res_getPrimeQ = retrieveKeyFromServer("primeQ");
	
	BIGNUM * primeQ = BN_new();
    BIGNUM * userKey = BN_new();
	
    BN_hex2bn(&primeQ, res_getPrimeQ);
    BN_hex2bn(&userKey, res_getUserK);

    User *u = new User();

    u->setPrimeQ(primeQ);
    u->setUserKey(userKey);
	
	unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * 80);
	/*message_to_send[0] = 'H';
	message_to_send[1] = 'O';
	message_to_send[2] = 'L';
	message_to_send[3] = 'A';
	message_to_send[4] = '\0';*/
    memcpy(message_to_send, "me cago en diosssssss", 21);
    message_to_send[22] = '\0';

    std::vector<std::pair <unsigned char*, unsigned int> > p;
    p = Base64Splitter(message_to_send, 22, 2);

    printf("Message splitted into: %d %s\n", p.size(), p[0].first);
	
	
	/*std::pair<unsigned char *, unsigned int> hashed_component = encodeIntoBase64(message_to_send, 5);
	std::pair<BIGNUM *, BIGNUM *> p1 = u->ContentProviderEnc(hashed_component.first, hashed_component.second);
	
	//delete u;
	
	BN_clear_free(primeQ);
	BN_clear_free(userKey);
	// END ONE OF THE WRAPPERS
	
	// BEGIN SERVER WRAPPER
	BIGNUM * router_primeQ = BN_new();
    BIGNUM * serverKey = BN_new();

    char * res_getServerK = retrieveKeyFromServer("serverK:0");
    char * res_router_getPrimeQ = retrieveKeyFromServer("primeQ");
        
    BN_hex2bn(&router_primeQ, res_router_getPrimeQ);
    BN_hex2bn(&serverKey, res_getServerK);

    CCN *router = new CCN();

    router->setPrimeQ(router_primeQ);
    router->setServerKey(serverKey);
	
	std::pair<BIGNUM *, BIGNUM *> p2 = router->ContentProviderReEnc(p1);
	
	if (BN_cmp(p1.first, p2.first))
	{
		printf("ERROR: first pair of ContentProviderEnc and ContentProviderReEnc are not equal, error\n");
		printDEBUG(*p1.first);
		printDEBUG(*p2.first);
		exit(-1);
	}
	
	//delete router;
	// END SERVER WRAPPER
	
	std::pair<BIGNUM *, BIGNUM *> p3 = router->CCNPreDec(p2);
	
	if (BN_cmp(p1.first, p3.first))
	{
		printf("ERROR: first pair of CCNPreDec and ContentProviderEnc are not equal, error\n");
		printDEBUG(*p1.first);
		printDEBUG(*p3.first);
		exit(-1);
	}
	
	if (BN_cmp(p1.second, p3.second))
	{
		printf("ERROR: second pair of CCNPreDec and ContentProviderEnc are not equal\n");
		printDEBUG(*p1.second);
		printDEBUG(*p3.second);
		exit(-1);
	}
	
	
	BIGNUM * res = u->UserDec(p3);
	unsigned char * res_char = (unsigned char *) calloc(sizeof(unsigned char), 150);
	BN_bn2bin(res, res_char);
	printf("The final result is:\n%s\n========================\n\n%s\n", res_char, hashed_component.first);
	
	if (memcmp((void *)res_char, (void *)hashed_component.first, hashed_component.second ) != 0)
	{
		printf("ERROR: The encrypted and decrypted strings are not equal\n");
		exit(-1);
	}
	// For this program
	delete u;
	
	printf("\n\n\n");*/
	
	/* The script repeats */
    char * example1;
    char * example2;
    char * example3;
    unsigned char * example4;
    std::vector< std::pair <unsigned char*, unsigned int> > rebuild_vector;
    unsigned int rebuild_size = 0;
    for(unsigned int j=0; j<p.size(); j++)
    {
	    example1 = EncryptUserContent(p[j].first, p[j].second);
	    example2 = libprotector_ReEncryptUserContent(example1, strlen(example1));
	    example3 = libprotector_DecryptContent(example2);
	    example4 = ReDecryptContent(example3);

        rebuild_vector.push_back(
            std::make_pair(example4, strlen(reinterpret_cast<const char*>(example4)) + 1)
        );
        rebuild_size += strlen(example4);

        free(example1);
        free(example2);
        free(example3);
        free(example4);
    }
	std::pair <unsigned char*, unsigned int> result = Base64Joiner(rebuild_vector, rebuild_size + 1);

    for(unsigned int j=0; j<p.size(); j++)
    {
        free(p[j].first);
    }

	printf("The received message after split/join is %s\n", result.first);

    free(result.first);

    return 1;
}
