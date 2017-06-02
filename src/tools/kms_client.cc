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

#include "utils.h"

int main(void)
{
    std::string * msg2 = new std::string("serverK:0");
    char * res = retrieveKeyFromServer(msg2->c_str());

	char * aux_component = NULL;
    aux_component = (char *) calloc(sizeof(char), (SECURITY_KEYSIZE/4 + 2));
    printf("%s\n",aux_component);
    free(aux_component);

    free(res);
    //delete msg1;
	delete msg2;
    return 0;
}
