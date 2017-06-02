#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include "user.h"

#define SECURITY_KEYSIZE 512

#define HOST    "192.168.1.1"
#define PORT_NUMBER 8992

#ifdef __cplusplus
    #include <utility>
    #include <string>
    #include <vector>
#endif /* __cplusplus */

#ifdef __cplusplus
std::pair<unsigned char*, unsigned int> hash_message(const char *mess1);
std::pair<unsigned char*, unsigned int> encodeIntoBase64(const unsigned char * message, const unsigned int message_len);
void printDEBUG(const BIGNUM var);
std::vector<std::pair <unsigned char*, unsigned int> > Base64Splitter(const unsigned char * message, const unsigned int message_len, const unsigned int max_block_size);
std::pair <unsigned char*, unsigned int> Base64Joiner(std::vector<std::pair <unsigned char*, unsigned int> > vec, unsigned int max_message_size);
#endif

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
unsigned char * EncryptAndSplitContent(const unsigned char * message, const unsigned int message_len, const unsigned int max_block_size, unsigned int * output_size);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
unsigned char * EncryptAndSplitContent_v2(const unsigned char * message, const unsigned int message_len, const unsigned int max_block_size, unsigned int * output_size);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
unsigned char * decodeFromBase64(unsigned char * b64_text, unsigned int b64_len);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
char * retrieveKeyFromServer(const char * key);

#endif
