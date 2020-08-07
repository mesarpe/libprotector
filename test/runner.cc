#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../src/lib/user.h"
#include "../src/lib/ccn.h"
#include "../src/lib/kms.h"

#include "../src/lib/utils.h"

TEST_CASE("Basic test of encryption/decryption without converting to base64 the values") {

    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * 5);
	message_to_send[0] = 'H';
	message_to_send[1] = 'O';
	message_to_send[2] = 'L';
	message_to_send[3] = 'A';
	message_to_send[4] = '\0';
	
	char * example1 = NULL;
    char * example2 = NULL;
    char * example3 = NULL;
    unsigned char * example4 = NULL;
    
    example1 = libprotector_EncryptUserContent(message_to_send, 5);
    example2 = libprotector_ReEncryptUserContent(example1, strlen((char *)example1));
    example3 = libprotector_DecryptContent(example2);
    example4 = libprotector_ReDecryptAndSplitContent(example3);
    CHECK_EQ(strcmp((char *) example4, "HOLA"), 0);
    
    free(example4);
    free(example3);
    free(example2);
    free(example1);
    
    free(message_to_send);
}

TEST_CASE("T1: test base64: encode and decode hola"){
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * 5);
	message_to_send[0] = 'H';
	message_to_send[1] = 'O';
	message_to_send[2] = 'L';
	message_to_send[3] = 'A';
	message_to_send[4] = '\0';
	
	std::pair <unsigned char*, unsigned int> inb64text = encodeIntoBase64(message_to_send, 5);
	//printf("This is how the b64 looks like: %s %s\n", inb64text.first, "SE9MQQo=");
	
	// SE9MQQo=, result obtained with the bash command: echo "HOLA" | base64
	//CHECK_EQ(inb64text.second, strlen("SE9MQQo="));
	//CHECK_EQ(strcmp((char *)inb64text.first, "SE9MQQo="), 0);
	
    unsigned char * decoded_base64_text = decodeFromBase64(inb64text.first, inb64text.second);
    
    free(inb64text.first);
    
    CHECK_EQ(strcmp((char *)decoded_base64_text, (char *)message_to_send), 0);
    
    free(decoded_base64_text);
    free(message_to_send);
}

TEST_CASE("T1: test base64: encode and decode Hello world"){
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * 12);
	message_to_send[0] = 'h';
	message_to_send[1] = 'e';
	message_to_send[2] = 'l';
	message_to_send[3] = 'l';
	message_to_send[4] = 'o';
	message_to_send[5] = ' ';
	message_to_send[6] = 'w';
	message_to_send[7] = 'o';
	message_to_send[8] = 'r';
	message_to_send[9] = 'l';
	message_to_send[10] = 'd';
	message_to_send[11] = '\0';
	
	std::pair <unsigned char*, unsigned int> inb64text = encodeIntoBase64(message_to_send, 12);
	//printf("This is how the b64 looks like: %s %s\n", inb64text.first, "SE9MQQo=");
	
	// SE9MQQo=, result obtained with the bash command: echo "HOLA" | base64
	//CHECK_EQ(inb64text.second, strlen("SGVsbG8gd29ybGQK"));
	//CHECK_EQ(strcmp((char *)inb64text.first, "SGVsbG8gd29ybGQK"), 0);
	
    unsigned char * decoded_base64_text = decodeFromBase64(inb64text.first, inb64text.second);
    
    free(inb64text.first);
    
    CHECK_EQ(strcmp((char *)decoded_base64_text, (char *)message_to_send), 0);
    
    free(decoded_base64_text);
    free(message_to_send);
}

TEST_CASE("T1: test base64: encode and decode A(63 times)"){
    unsigned int N = 23;
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * (N+1));
    
    
    for(int i=0; i<N; i++)
    {
	    message_to_send[i] = 'A';
    }
    message_to_send[N] = '\0';
	
	std::pair <unsigned char*, unsigned int> inb64text = encodeIntoBase64(message_to_send, N);
	//printf("This is how the b64 looks like: %s %s\n", inb64text.first, "SE9MQQo=");
	
	// SE9MQQo=, result obtained with the bash command: echo "HOLA" | base64
	//CHECK_EQ(inb64text.second, strlen("SGVsbG8gd29ybGQK"));
	//CHECK_EQ(strcmp((char *)inb64text.first, "SGVsbG8gd29ybGQK"), 0);

    unsigned char * decoded_base64_text = decodeFromBase64(inb64text.first, inb64text.second);
    
    free(inb64text.first);

    CHECK_EQ(strlen((char *)decoded_base64_text), N);
    CHECK_EQ(strlen((char *)message_to_send), N);
    
    CHECK_EQ(strcmp((char *)decoded_base64_text, (char *)message_to_send), 0);
    
    free(decoded_base64_text);
    free(message_to_send);
}

TEST_CASE("T1: test base64: encode and decode A(1000 times)"){
    unsigned int N = 1000;
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * (N+1));
    
    
    for(int i=0; i<N; i++)
    {
	    message_to_send[i] = 'A';
	}
	message_to_send[N] = '\0';
	
	std::pair <unsigned char*, unsigned int> inb64text = encodeIntoBase64(message_to_send, N);
	
	// SE9MQQo=, result obtained with the bash command: echo "HOLA" | base64
	//CHECK_EQ(inb64text.second, strlen("SGVsbG8gd29ybGQK"));
	//CHECK_EQ(strcmp((char *)inb64text.first, "SGVsbG8gd29ybGQK"), 0);
	
    unsigned char * decoded_base64_text = decodeFromBase64(inb64text.first, inb64text.second);
    
    free(inb64text.first);
    
    CHECK_EQ(strcmp((char *)decoded_base64_text, (char *)message_to_send), 0);
    
    free(decoded_base64_text);
    free(message_to_send);
}


TEST_CASE("T1: test base64: encode and decode A(1000 times)"){
    unsigned int N = 4000;
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * (N+1));
    
    
    for(int i=0; i<N; i++)
    {
	    message_to_send[i] = 'A';
	}
	message_to_send[N] = '\0';
	
	std::pair <unsigned char*, unsigned int> inb64text = encodeIntoBase64(message_to_send, N);
	
	// SE9MQQo=, result obtained with the bash command: echo "HOLA" | base64
	//CHECK_EQ(inb64text.second, strlen("SGVsbG8gd29ybGQK"));
	//CHECK_EQ(strcmp((char *)inb64text.first, "SGVsbG8gd29ybGQK"), 0);
	
    unsigned char * decoded_base64_text = decodeFromBase64(inb64text.first, inb64text.second);
    
    free(inb64text.first);
    
    CHECK_EQ(strcmp((char *)decoded_base64_text, (char *)message_to_send), 0);
    
    free(decoded_base64_text);
    free(message_to_send);
}

TEST_CASE("Basic test of encryption/decryption without converting to base64 the values") {
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * 5);
	message_to_send[0] = 'H';
	message_to_send[1] = 'O';
	message_to_send[2] = 'L';
	message_to_send[3] = 'A';
	message_to_send[4] = '\0';
	
	char * example1 = NULL;
    char * example2 = NULL;
    char * example3 = NULL;
    unsigned char * example4 = NULL;
    
    std::vector<std::pair <unsigned char*, unsigned int> > p;
    p = Base64Splitter(message_to_send, strlen((char *) message_to_send), 32);
    
    for(unsigned int j=0; j<p.size(); j++)
    {
        example1 = libprotector_EncryptUserContent(p[j].first, p[j].second);
        example2 = libprotector_ReEncryptUserContent(example1, strlen((char *)example1));
        example3 = libprotector_DecryptContent(example2);
        example4 = libprotector_ReDecryptAndSplitContent(example3);
        CHECK_EQ(strcmp((char *) example4, "HOLA"), 0);
        
        free(example4);
        free(example3);
        free(example2);
        free(example1);
    }
    
    free(message_to_send);
}

TEST_CASE("Test splitter/joiner 5 characters") {
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * 5);
	message_to_send[0] = 'H';
	message_to_send[1] = 'O';
	message_to_send[2] = 'L';
	message_to_send[3] = 'A';
	message_to_send[4] = '\0';

    std::vector<std::pair <unsigned char*, unsigned int> > p;
    p = Base64Splitter(message_to_send, strlen((char *) message_to_send), 32);
    
    std::pair <unsigned char*, unsigned int> result = Base64Joiner(p, 5);
    
    CHECK_EQ(strcmp((char *) message_to_send, (char *) result.first), 0);
    
    free(result.first);
    free(message_to_send);   
}

TEST_CASE("Test splitter/joiner 1000 characters"){
    unsigned int N = 1000;
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * (N+1));
    
    
    for(int i=0; i<N; i++)
    {
	    message_to_send[i] = 'A';
	}
	message_to_send[N] = '\0';
	
	std::vector<std::pair <unsigned char*, unsigned int> > p;
    p = Base64Splitter(message_to_send, strlen((char *) message_to_send), 32);
    
    std::pair <unsigned char*, unsigned int> result = Base64Joiner(p, N+1);
    
    CHECK_EQ(strcmp((char *) message_to_send, (char *) result.first), 0);
    
    free(result.first);
    free(message_to_send);
}

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
    
    // The script repeats
    char * example1 = NULL;
    char * example2 = NULL;
    char * example3 = NULL;
    unsigned char * example4 = NULL;
    std::vector< std::pair <unsigned char*, unsigned int> > rebuild_vector;
    unsigned int rebuild_size = 0;
    for(unsigned int j=0; j<p.size(); j++)
    {
	    example1 = libprotector_EncryptUserContent(p[j].first, p[j].second);
	    printf("EncryptUserContent: %s\n", example1);
	    
        example2 = libprotector_ReEncryptUserContent(example1, strlen((char *)example1));
        printf("ReEncryptUserContent: %s\n", example2);
        
        example3 = libprotector_DecryptContent(example2);
        printf("Pre-DecryptUserContent: %s\n", example3);
        
        // The problem seems to be the following
        // We are decoding the values in _redecryptcontent and also with base64 joiner
        // 
	    example4 = libprotector_ReDecryptContent(example3);

        unsigned int example4_size = strlen((char *)example4) + 1;
        rebuild_vector.push_back(std::make_pair(example4, example4_size));
        rebuild_size += example4_size;

        free(example3);
        free(example2);
        free(example1);
        
        //free(p[j].first);
    }
    
    std::pair <unsigned char*, unsigned int> result = Base64Joiner(rebuild_vector, rebuild_size + 1);

    for(unsigned int j=0; j<p.size(); j++)
    {
        free(p[j].first);
    }

	printf("The received message after split/join is %s (%d) (%d) -- %s\n", result.first, result.second, rebuild_size, message_to_send);
	
	CHECK_EQ(strcmp((char *) result.first, (char *)message_to_send), 0);
    
    free(message_to_send);
}


TEST_CASE("Repeat all the steps to encrypt and decrypt content"){
    // THIS TEST REQUIRES THAT the kms_server is running
    unsigned int N = 35;
    unsigned char * message_to_send = (unsigned char *) malloc(sizeof(unsigned char) * (N+1));
    
    
    for(int i=0; i<N; i++)
    {
	    message_to_send[i] = 'A';
	}
	message_to_send[N] = '\0';

    std::vector<std::pair <unsigned char*, unsigned int> > p;
    p = Base64Splitter(message_to_send, strlen((char *) message_to_send), 32);
    
    // The script repeats
    char * example1 = NULL;
    char * example2 = NULL;
    char * example3 = NULL;
    unsigned char * example4 = NULL;
    std::vector< std::pair <unsigned char*, unsigned int> > rebuild_vector;
    unsigned int rebuild_size = 0;
    for(unsigned int j=0; j<p.size(); j++)
    {
	    example1 = libprotector_EncryptUserContent(p[j].first, p[j].second);
	    printf("EncryptUserContent: %s\n", example1);
	    
        example2 = libprotector_ReEncryptUserContent(example1, strlen((char *)example1));
        printf("ReEncryptUserContent: %s\n", example2);
        
        example3 = libprotector_DecryptContent(example2);
        printf("Pre-DecryptUserContent: %s\n", example3);
        
        // The problem seems to be the following
        // We are decoding the values in _redecryptcontent and also with base64 joiner
        // 
	    example4 = libprotector_ReDecryptContent(example3);

        unsigned int example4_size = strlen((char *)example4) + 1;
        rebuild_vector.push_back(std::make_pair(example4, example4_size));
        rebuild_size += example4_size;

        free(example3);
        free(example2);
        free(example1);
        
        //free(p[j].first);
    }
    
    std::pair <unsigned char*, unsigned int> result = Base64Joiner(rebuild_vector, rebuild_size + 1);

    for(unsigned int j=0; j<p.size(); j++)
    {
        free(p[j].first);
    }

	printf("The received message after split/join is %s (%d) (%d) -- %s\n", result.first, result.second, rebuild_size, message_to_send);
	
	CHECK_EQ(strcmp((char *) result.first, (char *)message_to_send), 0);
    
    free(message_to_send);
}
