#include "ccn.h"

#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <string>
#include <cstring>
#include <utility>
#include <iterator>
#include <typeinfo>
#include <openssl/crypto.h>
#include <boost/algorithm/string.hpp>

#include "utils.h"

#include <openssl/evp.h>

CCN::CCN(unsigned int keysize)
{
    this->keysize = keysize;
	this->numberG = BN_new();
    BIGNUM * number1 = BN_new();
    BN_one(number1);
    BN_add(this->numberG, number1, number1);
    BN_clear_free(number1);
};

CCN::~CCN(void)
{
    if(this->numberX_2)
        BN_clear_free(this->numberX_2);
    if(this->primeQ)
        BN_clear_free(this->primeQ);
    BN_clear_free(this->numberG);
};

void CCN::setPrimeQ(const BIGNUM * Q)
{
    this->primeQ = BN_dup(Q);
};

void CCN::setServerKey(const BIGNUM * serverKey)
{
    this->numberX_2 = BN_dup(serverKey);
};

void CCN::setNumberG(const BIGNUM * my_g)
{
    this->numberG = BN_dup(my_g);
};

BIGNUM * CCN::CCNTD(const std::pair<BIGNUM *, BIGNUM *> T)
{
    BIGNUM * aux = BN_new();
    BN_CTX * ctx = BN_CTX_new();
    BN_mod_exp(aux, T.first, this->numberX_2, this->primeQ, ctx);
    BN_CTX_free(ctx);

    BIGNUM * res_aux = BN_new();
    ctx = BN_CTX_new();
    BN_mul(res_aux, aux, T.second, ctx);
    BN_CTX_free(ctx);

    BIGNUM * res = BN_new();
    ctx = BN_CTX_new();
    BN_mod(res, res_aux, this->primeQ, ctx);
    BN_CTX_free(ctx);

    BN_clear_free(res_aux);
    BN_clear_free(aux);
    

    return res;
}

char * CCN::FullCCNTD(const std::vector<std::pair<BIGNUM *, BIGNUM *> > * content_names)
{
    //printf("FULLCCNTD\n");
    //std::vector<BIGNUM *> * res = new std::vector<BIGNUM *>(content_names->size());

    char * new_content_name;
    unsigned int offset = 0;
    new_content_name = (char *) calloc(sizeof(char), content_names->size() * ((SECURITY_KEYSIZE/4) + 1 + 1) ); // TODO: 1 for the /, 1 for the \0

    std::vector<std::pair<BIGNUM *, BIGNUM *> >::const_iterator it;

    /* Initialize name */
    memcpy((void *) (new_content_name + offset), (void *) "/", 1 + 1);
    offset +=1;

    for (it = content_names->begin() ; it != content_names->end(); it++)
    {

        std::pair<BIGNUM *, BIGNUM *> pair_name = *it;
        
        //printDEBUG(*pair_name.first);
        //printDEBUG(*pair_name.second);
        BIGNUM * encrypted_bignum = this->CCNTD(pair_name);
        //printDEBUG(*encrypted_bignum);
        //res->push_back(encrypted_bignum);

        char * aux_component = BN_bn2hex(encrypted_bignum);
        memcpy((void *) (new_content_name + offset), (void *) aux_component, (SECURITY_KEYSIZE/4));
        offset +=(SECURITY_KEYSIZE/4);
        memcpy((void *) (new_content_name + offset), (void *) "/", 1 + 1);
        offset +=1;

        BN_clear_free(encrypted_bignum);
        OPENSSL_free(aux_component);
    }

    return new_content_name;
}

char * CCN::FullCCNTD(const char * user_encrypted_trapdoors) // This function receives the bignums encoded into a CCN name
{
    /* split in keywords */
    std::vector<std::string> keywords;
    boost::split(keywords, user_encrypted_trapdoors, boost::is_any_of("/"));


    std::vector<std::pair<BIGNUM *, BIGNUM *> > * vec = new std::vector<std::pair<BIGNUM *, BIGNUM *> >();
    
    // This hack is done because the first component is ndnx:
    std::vector<std::string>::iterator it = keywords.begin();
    std::advance(it, 1);

    for(; it < keywords.end(); it+=2)
    {
        std::string t1 = *it;
        if (t1.compare("") == 0)
        {
            std::advance(it, 1);
            if (it == keywords.end())
                break;
            t1 = *it;
        }
		
		if (t1.compare("") == 0 or t1.size() < SECURITY_KEYSIZE/4/2) // horrible hack to handle when the are options in the name
            continue;
   
        //printf("retrieved t1: %s\n", t1.c_str());
        std::string t2 = *boost::next(it);
        //printf("retrieved t2: %s\n", t2.c_str());

        if (t1.compare("") == 0 or t2.compare("") == 0 or t1.size() < SECURITY_KEYSIZE/4/2 or t2.size() < SECURITY_KEYSIZE/4/2) // horrible hack
            continue;

        BIGNUM *p1 = BN_new();
        BIGNUM *p2 = BN_new();

        const char * c1 = t1.c_str();
        const char * c2 = t2.c_str();
        //printf("THe number are: %s, %s\n", c1, c2);
        BN_hex2bn(&p1, c1);
        BN_hex2bn(&p2, c2);

        //printDEBUG(*p1);
        //printDEBUG(*p2);


        std::pair<BIGNUM *, BIGNUM *> utrapdoor = std::make_pair(p1, p2);

        vec->push_back(utrapdoor);    
    }

    char * res = this->FullCCNTD(vec);
    // free vec

    for(std::vector<std::pair<BIGNUM *, BIGNUM *> >::iterator it2 = vec->begin(); it2 != vec->end(); it2++)
    {
        std::pair<BIGNUM *, BIGNUM *> p = *it2;
        
        BN_clear_free(p.first);
        BN_clear_free(p.second);


    }
    delete vec;

    return res;
}

bool MatchTDs(const BIGNUM * a, const BIGNUM * b)
{
    return BN_cmp(a, b) == 0;
}

std::pair<BIGNUM *, BIGNUM *> CCN::ContentProviderReEnc(const std::pair<BIGNUM *, BIGNUM *> encrypted_payload)
{
	if(this->primeQ == NULL || this->numberG == NULL)
    {
        printf("Values not initialized\n");
        exit(-1);
    }
	
	BIGNUM * aux = BN_new();
	BN_CTX * ctx = BN_CTX_new();
	BN_mod_exp(aux, encrypted_payload.first, this->numberX_2, this->primeQ, ctx);
	BN_CTX_free(ctx);
	
	//Create duplicate of first pair
	BIGNUM * t_1 = BN_dup(encrypted_payload.first);
	
	// Multiply by second pair
	BIGNUM * t_2 = BN_new();
	ctx = BN_CTX_new();
	BN_mod_mul(t_2,  aux, encrypted_payload.second, this->primeQ, ctx);
	BN_CTX_free(ctx);
	
	BN_clear_free(aux);
	
	return std::make_pair(t_1, t_2);
}

std::pair<BIGNUM *, BIGNUM *> CCN::CCNPreDec(const std::pair<BIGNUM *, BIGNUM *> encrypted_payload)
{
	//TODO: add this value to global
	
	if(this->primeQ == NULL || this->numberG == NULL || this->numberX_2 == NULL)
    {
        printf("Values not initialized\n");
        exit(-1);
    }
	
	BIGNUM * t_1 = BN_dup(encrypted_payload.first);
	
	BIGNUM * aux = BN_new();
	BN_CTX * ctx = BN_CTX_new();
	BN_mod_exp(aux, encrypted_payload.first, this->numberX_2, this->primeQ, ctx);
	BN_CTX_free(ctx);
	
	ctx = BN_CTX_new();
	BIGNUM * aux2 = BN_new();
	aux2 = BN_mod_inverse(aux2, aux, this->primeQ, ctx);
	BN_CTX_free(ctx);
	
	if (aux2 == NULL)
	{
		printf("CCNPreDec:The calculus of the inverse has failed\n");
		exit(-1);
	}
	
	BIGNUM * t_2 = BN_new();
	ctx = BN_CTX_new();
	BN_mod_mul(t_2,  aux2, encrypted_payload.second, this->primeQ, ctx);
	BN_CTX_free(ctx);
	
	BN_clear_free(aux);
	BN_clear_free(aux2);
	
	return std::make_pair(t_1, t_2);
}



/****** WRAPPER FOR USE IN A LIBRARY ************/
// Wrapper for C
extern "C" char * ReEncryptUserTD(const char * user_trapdoor, const BIGNUM * primeQ,  const BIGNUM * serverKey)
{
    CCN *router = new CCN(512); //TODO: CHANGE
    //printf("The router was created\n");

    router->setPrimeQ(primeQ);
    router->setServerKey(serverKey);
    //printf("The prime and server key also: %s\n", user_trapdoor);

    char * res = router->FullCCNTD(user_trapdoor);

    //printf("After the function: %s\n", res);

    delete router;

    return res;
}

extern "C" char * libprotector_SimpleReEncryptUserTD(const char * user_trapdoor)
{
    //printf("SimpleReEncryptUserTD\n");
    BIGNUM * primeQ = BN_new();
    BIGNUM * serverKey = BN_new();

    char * res_getServerK = retrieveKeyFromServer("serverK:0");
    char * res_getPrimeQ = retrieveKeyFromServer("primeQ");
        
    BN_hex2bn(&primeQ, res_getPrimeQ);
    BN_hex2bn(&serverKey, res_getServerK);

    CCN *router = new CCN(512); // TODO: change
    //printf("The router was created\n");

    router->setPrimeQ(primeQ);
    router->setServerKey(serverKey);
    ///printf("The prime and server key also: %s\n", user_trapdoor);

    //printf("Execute FullCCNTD: %s\n", user_trapdoor);
    char * res = router->FullCCNTD(user_trapdoor);



    //printf("After the function: %s\n", res);

    delete router;

	int length = strlen(res);
    //int length = strnlen(res, 1 + ((SECURITY_KEYSIZE/4 + 1)* vec->size() * 2) + 1 + 1);
    char * res_final = (char *) calloc(sizeof(char), 5 + length +1);
    std::strcpy(res_final, "ccnx:");
    std::strcat(res_final, res);

    free(res);

    free(res_getServerK);
    free(res_getPrimeQ);

    BN_clear_free(primeQ);
    BN_clear_free(serverKey);

    return res_final;
}

extern "C" char * libprotector_ReEncryptUserContentNoNetwork(const char * user_encr_content, const unsigned int user_encr_len, const BIGNUM * serverKey, const BIGNUM * router_primeQ)
{
    CCN *router = new CCN(512); //TODO: CHANGE

    router->setPrimeQ(router_primeQ);
    router->setServerKey(serverKey);
	
	/* Convert char into BIGNUM */
	std::vector<std::string> keywords;
    boost::split(keywords, user_encr_content, boost::is_any_of("|"));

	BIGNUM *b1 = BN_new();
	BIGNUM *b2 = BN_new();

    //printf("Parts to be re-encrypted: %d\n", keywords.size());

	const char * c1 = keywords[0].c_str();
	const char * c2 = keywords[1].c_str();
	BN_hex2bn(&b1, c1);
	BN_hex2bn(&b2, c2);

	std::pair<BIGNUM *, BIGNUM *> content_trapdoor = std::make_pair(b1, b2);
	
	std::pair<BIGNUM *, BIGNUM *> p2 = router->ContentProviderReEnc(content_trapdoor);
	
	char * first_part_encr = BN_bn2hex(p2.first);
	char * second_part_encr = BN_bn2hex(p2.second);
	
	BN_clear_free(p2.first);
	BN_clear_free(p2.second);
	
	/* pack both in a string: append both parts with a pipe */
    char *reencrypted_content = (char*) calloc(sizeof(char), (SECURITY_KEYSIZE/4 + 1) * 2 + 1 + 1);
    strcpy(reencrypted_content, first_part_encr);
	strcat(reencrypted_content, "|");
    strcat(reencrypted_content, second_part_encr);
	
	/*Free all the generated value */
	BN_clear_free(b1);
	BN_clear_free(b2);
	
	delete router;
	
	OPENSSL_free(first_part_encr);
	OPENSSL_free(second_part_encr);
	
	return reencrypted_content;
}

extern "C" char * libprotector_ReEncryptUserContentWithKeys(const char * user_encr_content, const unsigned int user_encr_len, const char * res_getServerKey, const char * res_router_getPrimeQ)
{
    BIGNUM * router_primeQ = BN_new();
    BIGNUM * serverKey = BN_new();
    
    BN_hex2bn(&router_primeQ, res_router_getPrimeQ);
    BN_hex2bn(&serverKey, res_getServerKey);

    char * res = libprotector_ReEncryptUserContentNoNetwork(user_encr_content, user_encr_len, serverKey, router_primeQ);
    
	BN_clear_free(serverKey);
	BN_clear_free(router_primeQ);
	
	return res;
}

extern "C" char * libprotector_ReEncryptUserContent(const char * user_encr_content, const unsigned int user_encr_len)
{
	char * res_getServerK = retrieveKeyFromServer("serverK:0");
    char * res_router_getPrimeQ = retrieveKeyFromServer("primeQ");
        
    char * res = libprotector_ReEncryptUserContentWithKeys(user_encr_content, user_encr_len, res_getServerK, res_router_getPrimeQ);
	
	free(res_router_getPrimeQ);
	free(res_getServerK);
    
    return res;

    /**
    CCN *router = new CCN(512); //TODO: CHANGE

    router->setPrimeQ(router_primeQ);
    router->setServerKey(serverKey);
	
	// Convert char into BIGNUM
	std::vector<std::string> keywords;
    boost::split(keywords, user_encr_content, boost::is_any_of("|"));

	BIGNUM *b1 = BN_new();
	BIGNUM *b2 = BN_new();

    //printf("Parts to be re-encrypted: %d\n", keywords.size());

	const char * c1 = keywords[0].c_str();
	const char * c2 = keywords[1].c_str();
	BN_hex2bn(&b1, c1);
	BN_hex2bn(&b2, c2);

	std::pair<BIGNUM *, BIGNUM *> content_trapdoor = std::make_pair(b1, b2);
	
	std::pair<BIGNUM *, BIGNUM *> p2 = router->ContentProviderReEnc(content_trapdoor);
	
	char * first_part_encr = BN_bn2hex(p2.first);
	char * second_part_encr = BN_bn2hex(p2.second);
	
	// pack both in a string: append both parts with a pipe
    char *reencrypted_content = (char*) calloc(sizeof(char), (SECURITY_KEYSIZE/4 + 1) * 2 + 1 + 1);
    strcpy(reencrypted_content, first_part_encr);
	strcat(reencrypted_content, "|");
    strcat(reencrypted_content, second_part_encr);
	
	//Free all the generated value
	BN_clear_free(b1);
	BN_clear_free(b2);
	
	delete router;
	
	OPENSSL_free(first_part_encr);
	OPENSSL_free(second_part_encr);
	
	return reencrypted_content;**/
}

extern "C" char * libprotector_ReEncryptAndSplitUserContent(const char * user_encr_content, const unsigned int user_encr_len)
{
	BIGNUM * router_primeQ = BN_new();
    BIGNUM * serverKey = BN_new();

    char * res_getServerK = retrieveKeyFromServer("serverK:0");
    char * res_router_getPrimeQ = retrieveKeyFromServer("primeQ");
        
    BN_hex2bn(&router_primeQ, res_router_getPrimeQ);
    BN_hex2bn(&serverKey, res_getServerK);

    CCN *router = new CCN(512); //TODO: CHANGE

    router->setPrimeQ(router_primeQ);
    router->setServerKey(serverKey);
	
	/* Convert char into BIGNUM */
	std::vector<std::string> keywords;
    boost::split(keywords, user_encr_content, boost::is_any_of("|"));

    char *reencrypted_content = (char*) calloc(sizeof(char), (SECURITY_KEYSIZE/4 + 1) * keywords.size() + 1 + 1);

    for(unsigned int i=0; i<keywords.size(); i+=2)
    {
	    BIGNUM *b1 = BN_new();
	    BIGNUM *b2 = BN_new();

        //printf("Parts to be re-encrypted (libprotector_ReEncryptAndSplitUserContent): %u\n", keywords.size());

	    const char * c1 = keywords[i].c_str();
	    const char * c2 = keywords[i+1].c_str();
	    BN_hex2bn(&b1, c1);
	    BN_hex2bn(&b2, c2);

	    std::pair<BIGNUM *, BIGNUM *> content_trapdoor = std::make_pair(b1, b2);
	
	    std::pair<BIGNUM *, BIGNUM *> p2 = router->ContentProviderReEnc(content_trapdoor);
	
	    char * first_part_encr = BN_bn2hex(p2.first);
	    char * second_part_encr = BN_bn2hex(p2.second);
	
	    /* pack both in a string: append both parts with a pipe */
        
        strcat(reencrypted_content, first_part_encr);
	    strcat(reencrypted_content, "|");
        strcat(reencrypted_content, second_part_encr);
        // Dont add the character if its the last char
        if(i + 2 != keywords.size()) 
            strcat(reencrypted_content, "|");
	
	    /*Free all the generated value */
	    BN_clear_free(b1);
	    BN_clear_free(b2);

        OPENSSL_free(first_part_encr);
    	OPENSSL_free(second_part_encr);
    }

    printf("OUTPUT: %s\n", reencrypted_content);
	
	delete router;
	
	return reencrypted_content;
}

extern "C" char * libprotector_DecryptContentWithKeys(const char * reencrypted_content, const char * res_getServerK, const char * res_router_getPrimeQ)
{
    BIGNUM * router_primeQ = BN_new();
    BIGNUM * serverKey = BN_new();

    BN_hex2bn(&router_primeQ, res_router_getPrimeQ);
    BN_hex2bn(&serverKey, res_getServerK);

    CCN *router = new CCN(512); // TODO: CHANGE

    router->setPrimeQ(router_primeQ);
    router->setServerKey(serverKey);
	
	/* Convert char into BIGNUM */
	std::vector<std::string> keywords;
    boost::split(keywords, reencrypted_content, boost::is_any_of("|"));

	BIGNUM *b1 = BN_new();
	BIGNUM *b2 = BN_new();

	const char * c1 = keywords[0].c_str();
	const char * c2 = keywords[1].c_str();
	BN_hex2bn(&b1, c1);
	BN_hex2bn(&b2, c2);

	std::pair<BIGNUM *, BIGNUM *> content_trapdoor = std::make_pair(b1, b2);
	
	std::pair<BIGNUM *, BIGNUM *> p3 = router->CCNPreDec(content_trapdoor);
	
    char * first_part_encr = BN_bn2hex(p3.first);
	char * second_part_encr = BN_bn2hex(p3.second);
	
	/* pack both in a string: append both parts with a pipe */
    char *decrypted_content = (char*) calloc(sizeof(char), (SECURITY_KEYSIZE/4 + 1) * 2 + 1 + 1);
    strcpy(decrypted_content, first_part_encr);
	strcat(decrypted_content, "|");
    strcat(decrypted_content, second_part_encr);
	
	/*Free all the generated value */
	BN_clear_free(p3.first);
	BN_clear_free(p3.second);
	BN_clear_free(b1);
    BN_clear_free(b2);
	
	delete router;
	
	OPENSSL_free(first_part_encr);
	OPENSSL_free(second_part_encr);
	
	
	BN_clear_free(serverKey);
	BN_clear_free(router_primeQ);
	
	return decrypted_content;
}

extern "C" char * libprotector_DecryptContent(const char * reencrypted_content)
{
    char * res_getServerK = retrieveKeyFromServer("serverK:0");
    char * res_router_getPrimeQ = retrieveKeyFromServer("primeQ");
    
	char * decrypted_content = libprotector_DecryptContentWithKeys(reencrypted_content, res_getServerK, res_router_getPrimeQ);

	free(res_router_getPrimeQ);
	free(res_getServerK);
	
	return decrypted_content;
}


extern "C" char * libprotector_DecryptAndSplitContent(const char * reencrypted_content)
{
	BIGNUM * router_primeQ = BN_new();
    BIGNUM * serverKey = BN_new();

    char * res_getServerK = retrieveKeyFromServer("serverK:0");
    char * res_router_getPrimeQ = retrieveKeyFromServer("primeQ");
        
    BN_hex2bn(&router_primeQ, res_router_getPrimeQ);
    BN_hex2bn(&serverKey, res_getServerK);

    CCN *router = new CCN(512); // TODO: CHANGE

    router->setPrimeQ(router_primeQ);
    router->setServerKey(serverKey);
	
	/* Convert char into BIGNUM */
	std::vector<std::string> keywords;
    boost::split(keywords, reencrypted_content, boost::is_any_of("|"));

    //printf("Parts to be re-encrypted (libprotector_DecryptAndSplitContent): %u\n", keywords.size());

    char *decrypted_content = (char*) calloc(sizeof(char), (SECURITY_KEYSIZE/4 + 1) * keywords.size() + 1 + 1);
    decrypted_content[0] = '\0';

    for(unsigned int i = 0; i< keywords.size(); i+=2)
    {
	    BIGNUM *b1 = BN_new();
	    BIGNUM *b2 = BN_new();

	    const char * c1 = keywords[i].c_str();
	    const char * c2 = keywords[i+1].c_str();
	    BN_hex2bn(&b1, c1);
	    BN_hex2bn(&b2, c2);

	    std::pair<BIGNUM *, BIGNUM *> content_trapdoor = std::make_pair(b1, b2);
	
	    std::pair<BIGNUM *, BIGNUM *> p3 = router->CCNPreDec(content_trapdoor);
	
	    char * first_part_encr = BN_bn2hex(p3.first);
	    char * second_part_encr = BN_bn2hex(p3.second);
	
	    /* pack both in a string: append both parts with a pipe */
        strcat(decrypted_content, first_part_encr);
	    strcat(decrypted_content, "|");
        strcat(decrypted_content, second_part_encr);
        // Dont add the character if its the last char
        if(i + 2 != keywords.size()) 
            strcat(decrypted_content, "|");
	
	    /*Free all the generated value */
	    BN_clear_free(b1);
	    BN_clear_free(b2);	
	
	    OPENSSL_free(first_part_encr);
	    OPENSSL_free(second_part_encr);
    }

    delete router;

    printf("OUTPUT: %s\n", decrypted_content);
	
	return decrypted_content;
}





/* libprotector C interface */
extern "C" CCN * libprotector_CCN_new(unsigned int keysize)
{
    return new CCN(keysize);
}

extern "C" void libprotector_CCN_setServerKey(CCN * c, const char * proxy_key)
{
    BIGNUM * aux = BN_new();
    BN_hex2bn(&aux, proxy_key);
    reinterpret_cast<CCN *>(c)->setServerKey(aux);
    BN_clear_free(aux);
};

extern "C" void libprotector_CCN_setNumberG(CCN * c, const char * number_g)
{
    BIGNUM * aux = BN_new();
    BN_hex2bn(&aux, number_g);
    reinterpret_cast<CCN *>(c)->setNumberG(aux);
    BN_clear_free(aux);
};

extern "C" void libprotector_CCN_setPrimeQ(CCN * c, const char * prime_q)
{
    BIGNUM * aux = BN_new();
    BN_hex2bn(&aux, prime_q);
    reinterpret_cast<CCN *>(c)->setPrimeQ(aux);
    BN_clear_free(aux);
};

/*extern "C" void libprotector_CCN_setSalt(CCN * c, const char * salt_key)
{
    BIGNUM * aux = BN_new();
    BN_hex2bn(&aux, salt_key);
    reinterpret_cast<CCN *>(c)->setSalt(aux);
    BN_clear_free(aux);
};*/

extern "C" void libprotector_CCN_CCNTD(CCN * c, const char * component1, const char * component2, char *& p1)
{
    unsigned int keysize = reinterpret_cast<CCN *>(c)->keysize;;
    
    BIGNUM * aux = BN_new();
    BN_hex2bn(&aux, component1);
    
    BIGNUM * aux2 = BN_new();
    BN_hex2bn(&aux2, component2);
    
    std::pair<BIGNUM *, BIGNUM *> my_pair = std::make_pair(aux, aux2);
    
    BIGNUM * p = reinterpret_cast<CCN *>(c)->CCNTD(my_pair);
    
    p1 = (char *) calloc(sizeof(char), ((keysize/4)) );
    char * aux_component = BN_bn2hex(p);
    memcpy((void *) (p1), (void *) aux_component, (keysize/4));
    
    
    free(aux_component);
}

extern "C" void libprotector_CCN_CCNContentTD(CCN * c, const char * component1, const char * component2, char *& p1, char *& p2)
{
    unsigned int keysize = reinterpret_cast<CCN *>(c)->keysize;
    
    BIGNUM * aux = BN_new();
    BN_hex2bn(&aux, component1);
    
    BIGNUM * aux2 = BN_new();
    BN_hex2bn(&aux2, component2);
    
    std::pair<BIGNUM *, BIGNUM *> encrypted_payload = std::make_pair(aux, aux2);
    
    std::pair<BIGNUM *, BIGNUM *> p = reinterpret_cast<CCN *>(c)->ContentProviderReEnc(encrypted_payload);
    
    p1 = (char *) calloc(sizeof(char), ((keysize/4)) );
    char * aux_component = BN_bn2hex(p.first);
    memcpy((void *) (p1), (void *) aux_component, (keysize/4));
    
    p2 = (char *) calloc(sizeof(char), ((keysize/4)) );
    char * aux_component2 = BN_bn2hex(p.second);
    memcpy((void *) (p2), (void *) aux_component2, (keysize/4));
    
    free(aux_component);
    free(aux_component2);
}

extern "C" void libprotector_CCN_CCNContentPreDec(CCN * c, const char * component1, const char * component2, char *& p1, char *& p2)
{
    unsigned int keysize = reinterpret_cast<CCN *>(c)->keysize;
    
    BIGNUM * aux = BN_new();
    BN_hex2bn(&aux, component1);
    
    BIGNUM * aux2 = BN_new();
    BN_hex2bn(&aux2, component2);
    
    std::pair<BIGNUM *, BIGNUM *> encrypted_payload = std::make_pair(aux, aux2);
    
    std::pair<BIGNUM *, BIGNUM *> p = reinterpret_cast<CCN *>(c)->CCNPreDec(encrypted_payload);
    
    p1 = (char *) calloc(sizeof(char), ((keysize/4)) );
    char * aux_component = BN_bn2hex(p.first);
    memcpy((void *) (p1), (void *) aux_component, (keysize/4));
    
    p2 = (char *) calloc(sizeof(char), ((keysize/4)) );
    char * aux_component2 = BN_bn2hex(p.second);
    memcpy((void *) (p2), (void *) aux_component2, (keysize/4));
    
    free(aux_component);
    free(aux_component2);
}

