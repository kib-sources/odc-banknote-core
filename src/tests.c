/*#include <gtest/gtest.h>
#include "common.h"

TEST(get_hash_sha512, BasicAssertions) {
  unsigned char test[129];
  //get_hash_sha512("string", test);
  const unsigned char* result = reinterpret_cast<const unsigned char *>("2757cb3cafc39af451abb2697be79b4ab61d63d74d85b0418629de8c26811b529f3f3780d0150063ff55a2beee74c4ec102a2a2731a1f1f7f10d473ad18a6a87");
  EXPECT_EQ(test, result);
}*/
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "common.h"
 
void TEST1_SHA512()
{
  unsigned char test[129];
  get_hex_hash_sha512("string", test);
  unsigned char* result = ("2757cb3cafc39af451abb2697be79b4ab61d63d74d85b0418629de8c26811b529f3f3780d0150063ff55a2beee74c4ec102a2a2731a1f1f7f10d473ad18a6a87");
  int res = strcmp(test, result);
  printf("***TEST1_SHA512***\n");
  printf("Produced result: \n\t %s \n", test);
  printf("Expected result: \n\t %s \n", result);
  if (res == 0) {
    printf("TEST1_SHA512 passed!\n");
  } else {
    printf("TEST1_SHA512 failed!\n");
  }
}

void TEST2_SHA512()
{
  unsigned char test[129];
  get_hex_hash_sha512("important", test);
  unsigned char* result = ("09cdb9fc303c7ceaa74c5427dee2b09bec82338b2fc6cab21e54130a353b2b0a86bde09bbe27b0597789a7868a548406c5dfd057964a7e88441adbe0af1b357e");
  int res = strcmp(test, result);
  printf("***TEST2_SHA512***\n");
  printf("Produced result: \n\t %s \n", test);
  printf("Expected result: \n\t %s \n", result);
  if (res == 0) {
    printf("TEST2_SHA512 passed!\n");
  } else {
    printf("TEST2_SHA512 failed!\n");
  }
}

void TEST3_SHA512()
{
  unsigned char test[129];
  get_hex_hash_sha512("qwerty", test);
  unsigned char* result = ("0dd3e512642c97ca3f747f9a76e374fbda73f9292823c0313be9d78add7cdd8f72235af0c553dd26797e78e1854edee0ae002f8aba074b066dfce1af114e32f8");
  int res = strcmp(test, result);
  printf("***TEST3_SHA512***\n");
  printf("Produced result: \n\t %s \n", test);
  printf("Expected result: \n\t %s \n", result);
  if (res == 0) {
    printf("TEST3_SHA512 passed!\n");
  } else {
    printf("TEST3_SHA512 failed!\n");
  }
}


void TEST1_RSA()
{
  KEYS_PAIR bk = init_rsa_keys();
  SIGN sign;
  char* plainText = "My message\n";
  
  get_signature_rsa4096(plainText, bk.private, sign);
	
  int authentic = verify_signature_rsa4096(plainText, bk.public, sign);
  
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
  KEYS_PAIR bk = init_rsa_keys();
  SIGN sign;
  char* plainText = "Very very important\n";
  get_signature_rsa4096(plainText, bk.private, sign);
	
  int authentic = verify_signature_rsa4096(plainText, bk.public, sign);
  
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