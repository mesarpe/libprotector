#include "kms.h"
#include "utils.h"

#include <openssl/bn.h>

#define TRUE 1

KMS::KMS(void)
{
	this->table_user_keys = new MyHashTable();
	this->table_server_keys = new MyHashTable();
};

KMS::~KMS(void)
{
    if (this->primeP)
        BN_clear_free(this->primeP);
    if (this->primeQ)
        BN_clear_free(this->primeQ);
    if (this->numberG)
        BN_clear_free(this->numberG);
    if (this->numberX)
        BN_clear_free(this->numberX);
    if (this->secretH)
        BN_clear_free(this->secretH);
    if (this->numberS)
        BN_clear_free(this->numberS);
		
	delete this->table_user_keys;
	delete this->table_server_keys;
}

int KMS::InitKMS(int nr_bits)
{
    this->nr_bits = nr_bits;
    
    BIGNUM * number1 = NULL;
    BIGNUM * remainder = NULL;
    BIGNUM * aux = NULL;

    /* Get prime P */
    this->primeP = BN_new();
    int res = BN_generate_prime_ex(this->primeP, this->nr_bits, TRUE, NULL, NULL, NULL);
    //printDEBUG(*this->primeP);

    if (res == 0)
        exit(1);

    /* Calculate G */
    number1 = BN_new();
    BN_one(number1);
    this->numberG = BN_new();
    BN_add(this->numberG, number1, number1);

    /* Get prime Q */
    BN_CTX * ctx = BN_CTX_new();
    this->primeQ = BN_new();
    aux = BN_new();
    remainder = BN_new();
    BN_sub(aux, this->primeP, number1); // P - 1
    BN_div(this->primeQ, NULL, aux, this->numberG, ctx); // (P - 1) / 2
    BN_clear_free(aux);
    BN_CTX_free(ctx);

    BN_clear_free(remainder);
    BN_clear_free(number1);

    if((remainder == NULL) || (!BN_is_zero(remainder)))
    { // There is a problem, the remainder is not zero
        exit(1);
    }
    
    

    /* Calculate X and h: x \belongs \sum^{*}_{q} */
    aux = BN_new();
    this->secretH = BN_new();
    this->numberX = BN_new();

    BN_rand(aux, this->nr_bits, -1, 0);
    ctx = BN_CTX_new();
    BN_mod_exp(this->numberX, this->numberG, aux, this->primeQ, ctx);
    BN_CTX_free(ctx);

    ctx = BN_CTX_new();
    BN_mod_exp(this->secretH, this->numberG, this->numberX, this->primeP, ctx);
    BN_CTX_free(ctx);

    BN_clear_free(aux);

    /* Number S */
    this->numberS = BN_new();
    BN_rand(this->numberS, this->nr_bits, -1, 0);

    /* print generated values */
    //printDEBUG(*this->primeP); printf(" number P\n");
    //printDEBUG(*this->primeQ); printf(" number Q\n");
    //printDEBUG(*this->secretH); printf(" secret H\n");

    return 0;
};

std::pair<BIGNUM *, BIGNUM *> KMS::keyGenKMS()
{
    BIGNUM * numberX_1 = BN_new();
    BIGNUM * numberX_2 = BN_new();
    
    /* calculate random X_{i,1}*/
    BIGNUM * aux = BN_new();
    BN_rand(aux, this->nr_bits, -1, 0);
    BN_CTX * ctx = BN_CTX_new();
    BN_mod_exp(numberX_1, this->numberG, aux, this->primeQ, ctx);
    BN_CTX_free(ctx);
    BN_clear_free(aux);


    /* Calculate X_{i,2} */
    BN_sub(numberX_2, this->numberX, numberX_1);

    // The user receives numberX_1 and the server numberX_2
    return std::make_pair(numberX_1, numberX_2);
};

unsigned int KMS::addUser(void)
{
	// TODO: check if the key already exists
	
	std::pair<BIGNUM *, BIGNUM *> keys = this->keyGenKMS();
	
	char * user_side_key = BN_bn2hex(keys.first);
	char * server_side_key = BN_bn2hex(keys.second);
	
	unsigned int index = table_user_keys->size();
	
	if (index != table_server_keys->size())
	{
		printf("The number of keys in the user and server keystore does not match.");
		return -1;
	}
	
	
	this->table_user_keys->addElement(std::to_string(index), user_side_key);
	this->table_server_keys->addElement(std::to_string(index), server_side_key);
	
	return index;
}

BIGNUM * KMS::getPrimeQ(void)
{
    BIGNUM * Q = BN_dup(this->primeQ);
    return Q;
}

char * KMS::getServerKey(unsigned int index)
{
	std::string index_string = std::to_string(index).c_str();
    std::string Q = this->table_server_keys->lookup(index_string);
	
	char * res = (char *) malloc(sizeof(char) * Q.size()  );
	strcpy(res, Q.c_str());
    return res;
}

char * KMS::getUserKey(unsigned int index)
{
	std::string index_string = std::to_string(index).c_str();
    std::string Q = this->table_user_keys->lookup(index_string);
    char * res = (char *) malloc(sizeof(char) * Q.size()  );
	strcpy(res, Q.c_str());
    return res;
}

