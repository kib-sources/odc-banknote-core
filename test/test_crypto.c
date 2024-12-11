#include "unity.c"
#include "common.h"

void setUp(void) {};
void tearDown(void) {};

// подумать над именами

void test_sha512_1()
{
    HASH test_hash;
    _get_hash_sha512("string", test_hash);
    
    unsigned char hash[128];
    for(int i = 0; i < HASH_SIZE; i++) {
        sprintf(hash + (i * 2), "%02x", test_hash[i]);
    }
    hash[128] = 0;

    unsigned char* result = ("2757cb3cafc39af451abb2697be79b4ab61d63d74d85b0418629de8c26811b529f3f3780d0150063ff55a2beee74c4ec102a2a2731a1f1f7f10d473ad18a6a87");
    
    TEST_ASSERT_EQUAL_STRING(result, hash);
}

void test_sha512_2()
{
    HASH test_hash;
    _get_hash_sha512("important", test_hash);
    
    unsigned char hash[128];
    for(int i = 0; i < HASH_SIZE; i++) {
        sprintf(hash + (i * 2), "%02x", test_hash[i]);
    }
    hash[128] = 0;

    unsigned char* result = ("09cdb9fc303c7ceaa74c5427dee2b09bec82338b2fc6cab21e54130a353b2b0a86bde09bbe27b0597789a7868a548406c5dfd057964a7e88441adbe0af1b357e");
    
    TEST_ASSERT_EQUAL_STRING(result, hash);
}


void test_rsa4096_1()
{
    KEYS_PAIR bk = _init_rsa_keys();
    SIGN sign;
    char* plain_text = "My message\n";
  
    _get_signature_rsa4096(plain_text, bk.private, sign);
	
    int authentic = _verify_signature_rsa4096(plain_text, bk.public, sign);
    
    //0 - authentic
    TEST_ASSERT_EQUAL_INT(0, authentic);
}


void test_rsa4096_2()
{
    KEYS_PAIR bk = _init_rsa_keys();
    SIGN sign;
    char* plain_text = "Very very important\n";
  
    _get_signature_rsa4096(plain_text, bk.private, sign);
	
    int authentic = _verify_signature_rsa4096(plain_text, bk.public, sign);
    
    //0 - authentic
    TEST_ASSERT_EQUAL_INT(0, authentic);
}


int main(void)
{
    UNITY_BEGIN();
    
    RUN_TEST(test_sha512_1);
    RUN_TEST(test_sha512_2);

    RUN_TEST(test_rsa4096_1);
    RUN_TEST(test_rsa4096_2);
    
    UNITY_END();
    
    return 0;   
}