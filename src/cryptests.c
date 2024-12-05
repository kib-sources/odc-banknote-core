#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "common.h"

//Вынести тесты отдельно


void TEST1_SHA512()
{
    HASH test_hash;
    _get_hash_sha512("string", test_hash);
    
    unsigned char hash[128];
    for(int i = 0; i < HASH_SIZE; i++) {
        sprintf(hash + (i * 2), "%02x", test_hash[i]);
    }
    hash[128] = 0;

    unsigned char* result = ("2757cb3cafc39af451abb2697be79b4ab61d63d74d85b0418629de8c26811b529f3f3780d0150063ff55a2beee74c4ec102a2a2731a1f1f7f10d473ad18a6a87");
    
    int res = strcmp(hash, result);
    
    printf("***TEST1_SHA512***\n");
    printf("Produced result: \n\t %s \n", hash);
    printf("Expected result: \n\t %s \n", result);
    
    if (res == 0) {
        printf("TEST1_SHA512 passed!\n");
    } else {
        printf("TEST1_SHA512 failed!\n");
    }
}


void TEST2_SHA512()
{
    HASH test_hash;
    _get_hash_sha512("important", test_hash);
    
    unsigned char hash[128];
    for(int i = 0; i < HASH_SIZE; i++) {
        sprintf(hash + (i * 2), "%02x", test_hash[i]);
    }
    hash[128] = 0;

    unsigned char* result = ("09cdb9fc303c7ceaa74c5427dee2b09bec82338b2fc6cab21e54130a353b2b0a86bde09bbe27b0597789a7868a548406c5dfd057964a7e88441adbe0af1b357e");
    
    int res = strcmp(hash, result);
    
    printf("***TEST2_SHA512***\n");
    printf("Produced result: \n\t %s \n", hash);
    printf("Expected result: \n\t %s \n", result);
    
    if (res == 0) {
        printf("TEST2_SHA512 passed!\n");
    } else {
        printf("TEST2_SHA512 failed!\n");
    }
}


void TEST3_SHA512()
{
    HASH test_hash;
    _get_hash_sha512("important", test_hash);
    
    unsigned char hash[128];
    for(int i = 0; i < HASH_SIZE; i++) {
        sprintf(hash + (i * 2), "%02x", test_hash[i]);
    }
    hash[128] = 0;

    unsigned char* result = ("09cdb9fc303c7ceaa74c5427dee2b09bec82338b2fc6cab21e54130a353b2b0a86bde09bbe27b0597789a7868a548406c5dfd057964a7e88441adbe0af1b357e");
    
    int res = strcmp(hash, result);
    
    printf("***TEST3_SHA512***\n");
    printf("Produced result: \n\t %s \n", hash);
    printf("Expected result: \n\t %s \n", result);
    
    if (res == 0) {
        printf("TEST3_SHA512 passed!\n");
    } else {
        printf("TEST3_SHA512 failed!\n");
    }
}


void TEST1_RSA()
{
    KEYS_PAIR bk = _init_rsa_keys();
    SIGN sign;
    char* plain_text = "My message\n";
  
    _get_signature_rsa4096(plain_text, bk.private, sign);
	
    int authentic = _verify_signature_rsa4096(plain_text, bk.public, sign);
  
    if (authentic == 0 ) {
	    printf("Authentic\n");
    } else {
		printf("Not Authentic\n");
    }

    if (authentic == 0) {
        printf("TEST1_RSA passed!\n");
    } else {
        printf("TEST1_RSA failed!\n");
    }
}


void TEST2_RSA()
{
    KEYS_PAIR bk = _init_rsa_keys();
    SIGN sign;
    char* plain_text = "Very very important\n";
  
    _get_signature_rsa4096(plain_text, bk.private, sign);
	
    int authentic = _verify_signature_rsa4096(plain_text, bk.public, sign);
  
    if (authentic == 0 ) {
	    printf("Authentic\n");
    } else {
		printf("Not Authentic\n");
    }

    if (authentic == 0) {
        printf("TEST2_RSA passed!\n");
    } else {
        printf("TEST2_RSA failed!\n");
    }
}


void setup_tests()
{
    printf("**********TESTS**********\n");
    TEST1_SHA512();
    TEST2_SHA512();
    TEST3_SHA512();

	TEST1_RSA();
    TEST2_RSA();
    printf("**********TESTS END**********\n");
}