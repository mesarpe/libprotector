#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <string>
#include <cstring>
#include <utility>
#include <vector>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "utils.h"
#include "user.h"

/* Auxiliar functions*/
void printDEBUG(const BIGNUM var)
{
    BIO * out = NULL;
    out = BIO_new(BIO_s_file());

    if (out == NULL)
        exit(1);
	
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    BN_print(out, &var);
    printf("\n");

    CRYPTO_mem_leaks(out);
    BIO_free(out);
}

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

char * retrieveKeyFromServer(const char * key)
{
    // TODO: the 65 should be relative to the key size
    int key_size = SECURITY_KEYSIZE;
    int string_size = (key_size / 4 ) + 2;

    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char * recv_buffer = (char *) calloc(sizeof(char), string_size);
    portno = PORT_NUMBER;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    server = gethostbyname(HOST);
    //struct in_addr addr;
    //inet_aton(HOST, &addr);
    //server = gethostbyaddr(&addr, sizeof(addr), AF_INET);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");
    n = write(sockfd,key,strnlen(key, string_size));
    if (n < 0) 
         error("ERROR writing to socket");
    bzero(recv_buffer, string_size);
    n = read(sockfd,recv_buffer,string_size);
    if (n < 0) 
         error("ERROR reading from socket");
    //printf("%s\n",recv_buffer);
    close(sockfd);

    return recv_buffer;
}

std::pair <unsigned char*, unsigned int> hash_message(const char *mess1)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char * md_value = (unsigned char *) malloc(sizeof(unsigned char)*EVP_MAX_MD_SIZE);

    if (md_value == NULL)
        exit(1);

    unsigned int md_len;

    OpenSSL_add_all_digests();

    md = EVP_sha1();

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, mess1, strlen(mess1));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);

    //printf("Digest is: ");
    //for(i = 0; i < md_len; i++)
    //printf("%02x", md_value[i]);
    //printf("\n");

    // Call this once before exit.
    EVP_cleanup();

    return std::make_pair(md_value, md_len);
}

std::pair <unsigned char*, unsigned int> encodeIntoBase64(const unsigned char * message, const unsigned int message_len)
{
	
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, message, message_len);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);

	unsigned char *b64text = (unsigned char*) malloc((bufferPtr->length + 1) * sizeof(unsigned char));
	memcpy(b64text, bufferPtr->data, bufferPtr->length);
	b64text[bufferPtr->length] = '\0';
	
	int b64text_size = bufferPtr->length;
	BIO_free_all(b64);
	
	return std::make_pair(b64text, b64text_size);
}

size_t calcDecodeLength(const unsigned char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen((char *) b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

unsigned char * decodeFromBase64(unsigned char * b64_text, unsigned int b64_len)
{
	BIO *bio_dec, *b64_dec;
	
	int decodeLen = calcDecodeLength(b64_text);
	unsigned char * original_text = (unsigned char*)calloc(sizeof(unsigned char), decodeLen + 1);
	original_text[decodeLen] = '\0';

	bio_dec = BIO_new_mem_buf(b64_text, -1);
	b64_dec = BIO_new(BIO_f_base64());
	bio_dec = BIO_push(b64_dec, bio_dec);

	BIO_set_flags(bio_dec, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	/*int read_bytes = */BIO_read(bio_dec, original_text, b64_len);
	BIO_free_all(bio_dec);
	
	return original_text;
}


std::vector<std::pair <unsigned char*, unsigned int> > Base64Splitter(const unsigned char * message, const unsigned int message_len, const unsigned int max_block_size)
{
    unsigned int number_blocks = 0;

    if(message_len % max_block_size == 0)
        number_blocks = message_len / max_block_size;
    else
        number_blocks = (message_len / max_block_size) + 1;

    unsigned int offset_message = 0;

    std::vector< std::pair <unsigned char*, unsigned int> > block_vector;

    for(unsigned int i=0; i < number_blocks; i++)
    {
        unsigned int block_size = 0;
        if ( i == number_blocks -1)
            block_size = message_len % max_block_size;
        else
            block_size = max_block_size;
        
        unsigned char * block = (unsigned char*) calloc (sizeof(unsigned char), block_size+1);
        
        if (block == NULL)
        {
            printf("FATAL ERROR\n");
            exit(-1);
        }

        memcpy(block, message + offset_message, block_size);
        block[block_size] = '\0';
        offset_message += block_size;

        block_vector.push_back(std::make_pair(block, block_size+1));
    }

    return block_vector;
}

std::pair <unsigned char*, unsigned int> Base64Joiner(std::vector<std::pair <unsigned char*, unsigned int> > vec, unsigned int max_message_size)
{
    unsigned int offset_message = 0;
    unsigned char * message = (unsigned char*) calloc (sizeof(unsigned char), max_message_size);

    if(message == NULL)
    {
        printf("libprotector: no more memory\n");
        exit(-1);
    }

    for(unsigned int i=0; i < vec.size(); i++)
    {
        if (offset_message + vec[i].second > max_message_size)
        {
            printf("libprotector:The message is longer than expected (%d vs. %d) at iteration #%d\n", offset_message + vec[i].second, max_message_size, i);
            exit(-1);
        }
        
        if (vec[i].second - 1 >= 1)
        {
            memcpy(message + offset_message, vec[i].first, vec[i].second);
            offset_message += vec[i].second;
        }
    }
    message[offset_message] = '\0';

    return std::make_pair(message, offset_message + 1);
}



/* TODO: DEPRECATED FUNCTION */
unsigned char * EncryptAndSplitContent(const unsigned char * message, const unsigned int message_len, const unsigned int max_block_size, unsigned int * output_size)
{
    std::vector<std::pair <unsigned char*, unsigned int> > p;
    p = Base64Splitter(message, message_len, max_block_size);

    std::vector< std::pair <unsigned char*, unsigned int> > rebuild_vector;
    unsigned int rebuild_size = 0;
    unsigned char * example1;
    for(unsigned int j=0; j<p.size(); j++)
    {
        
	    example1 = (unsigned char *) libprotector_EncryptUserContent(p[j].first, p[j].second);

        rebuild_vector.push_back(std::make_pair(example1, strlen((char *) example1)));
        rebuild_size += strlen((char *) example1);
        //printf("%d rebuild_size %d %s %d\n", rebuild_size, p[j].second, p[j].first, strlen(example1));
    }


    std::pair <unsigned char*, unsigned int> result = Base64Joiner(rebuild_vector, rebuild_size);

    *output_size = result.second;

    return result.first;
}

unsigned char * EncryptAndSplitContent_v2(const unsigned char * original_message, const unsigned int original_message_len, const unsigned int max_block_size, unsigned int * output_size)
{
    std::pair<unsigned char *, unsigned int> hashed_component = encodeIntoBase64(original_message, original_message_len);
    const char * message = (char *) hashed_component.first;
    const unsigned int message_len = hashed_component.second;

    //printf("Message in base64 to be send (%d): %s\n", message_len, message);

    unsigned int number_blocks = 0;
    if(message_len % max_block_size == 0)
        number_blocks = message_len / max_block_size;
    else
        number_blocks = (message_len / max_block_size) + 1;

    unsigned char * encrypted_message = (unsigned char *) calloc(sizeof(unsigned char), (number_blocks * 2) * (SECURITY_KEYSIZE/4 + 1 + 2) + 1 + 1); // the 2 corresponds to the character to split
    encrypted_message[0] = '\0';
    unsigned int encr_message_len = 0;

    unsigned int block_nr = 0;
    unsigned char * aux = NULL;
    for(unsigned int i=1; i<=message_len; i++)
    {
        if(i % max_block_size == 0 || i == message_len)
        {
            aux = (unsigned char *) calloc(sizeof(unsigned char), max_block_size);
            memcpy(aux, message + block_nr * max_block_size, i - block_nr * max_block_size);
            
            // We can encrypt the value
            printf("Size of the encrypted value: %d\n", i - block_nr * max_block_size);
            unsigned char * example1 = (unsigned char *)  libprotector_EncryptUserContent(aux, i - block_nr * max_block_size);

            unsigned int e_size = strlen((char *)example1);
            strcat((char *)encrypted_message, (char *)example1);
            encr_message_len += e_size;
            if (i != message_len)
            {
                strcat((char *)encrypted_message, "|");
                encr_message_len += + 1;
            }

            block_nr = i / max_block_size;
        }
    }
    
    *output_size = encr_message_len;

    return encrypted_message;
}
