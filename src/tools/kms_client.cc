/**
 * Demo client for retrieving keys
 **/
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include <openssl/bn.h>

#include "../lib/utils.h"

int main(void)
{
    std::string * msg2 = new std::string("serverK:0");
    char * res = retrieveKeyFromServer(msg2->c_str());
    printf("Retrieved key: %s\n", res);
    free(res);
    delete msg2;
    return 0;
}
