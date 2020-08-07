/* A simple server that generates keys for the different users */
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bn.h>

#include <boost/algorithm/string.hpp>

#include "../lib/utils.h"
#include "../lib/kms.h"

int main(void)
{
    int key_size = SECURITY_KEYSIZE;
    int string_size = (key_size / 4 ) + 2;
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    char buffer[string_size];
    struct sockaddr_in serv_addr, cli_addr;
    int n;

    KMS * kms = new KMS();
    kms->InitKMS(key_size);
    // We add a user by default
    kms->addUser();

    std::pair<BIGNUM *, BIGNUM *> keys = kms->keyGenKMS();

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(PORT_NUMBER);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
          error("ERROR on binding");
    
    char * aux_component;
    while(1)
    {
        listen(sockfd, 5);
        clilen = sizeof(cli_addr);
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) 
            error("ERROR on accept");
        bzero(buffer,(SECURITY_KEYSIZE/4)+1);
        n = read(newsockfd,buffer,(SECURITY_KEYSIZE/4)+1);
        if (n < 0) error("ERROR reading from socket");

        

        std::string * msg = new std::string(buffer);
        if (msg->compare("primeQ") == 0)
        {
            aux_component = BN_bn2hex(kms->getPrimeQ());
            //printf("Here is the primeQ: %s\n",aux_component);
            n = write(newsockfd,aux_component, string_size+1);
            if (n < 0) error("ERROR writing to socket");
        }
		else if(msg->compare("addUser") == 0)
        {
			unsigned int new_id = kms->addUser();
			
            const char * aux_c = std::to_string(new_id).c_str();
			aux_component = (char *) malloc(sizeof(char) * (strlen(aux_c) + 1));
			aux_component = strcpy(aux_component, aux_c);
            //printf("New User Id: %s\n",aux_component);
            n = write(newsockfd,aux_component,string_size+1);
            if (n < 0) error("ERROR writing to socket");
        }
        /*else if(msg->compare("masterK") == 0)
        {
            aux_component = BN_bn2hex(keys.first);
            printf("Here is the MasterK: %s\n",aux_component);
            n = write(newsockfd,aux_component,string_size+1);
            if (n < 0) error("ERROR writing to socket");
        }*/
        else if(msg->compare(0, 5, "userK") == 0)
        {
            /*aux_component = BN_bn2hex(keys.first);
            printf("Here is the UserK: %s\n",aux_component);
            n = write(newsockfd,aux_component,string_size+1);
            if (n < 0) error("ERROR writing to socket");*/
            std::vector<std::string> parts2;
			boost::split(parts2, *msg, boost::is_any_of(":"));
			if (parts2.size() == 2)
			{
				aux_component = kms->getServerKey(std::stoul (parts2[1],nullptr,0));
				//printf("Here is the UserK: %s\n",aux_component);
				n = write(newsockfd,aux_component, string_size+1);
				if (n < 0) error("ERROR writing to socket");
			}
            else
                error("The User Key is not being requested correctly");
        }
        else if(msg->compare(0, 7, "serverK") == 0)
        {
			std::vector<std::string> parts;
			boost::split(parts, *msg, boost::is_any_of(":"));
			if (parts.size() == 2)
			{
				aux_component = kms->getServerKey(std::stoul (parts[1],nullptr,0));
				//printf("Here is the ServerK: %s\n",aux_component);
				n = write(newsockfd,aux_component, string_size+1);
				if (n < 0) error("ERROR writing to socket");
			}
            else
                error("The server Key is not being requested correctly");
        }
        else // Check if the message begins with S or U
        {
            n = write(newsockfd,"puto", string_size);
            if (n < 0) error("ERROR writing to socket");
        }
		close(newsockfd);
        delete msg;
    }
    close(sockfd);
    return 0; 
}
