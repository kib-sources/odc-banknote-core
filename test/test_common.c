#include <string.h>

#include "unity.c"
#include "common.h"

void setUp(void) {};
void tearDown(void) {};


void test_concatenation()
{
    int age = 16;
    char* name = "Anna";
    char* home = "City";
    char* delimiter = ";";

    char* concatenated = _concatenate_fields("ssdss", name, delimiter, age, delimiter, home);
    
    char* result = "Anna;16;City";
    TEST_ASSERT_EQUAL_STRING(result, concatenated);

    free(concatenated);
}


void test_generate_rand_salt()
{
    SALT rand_salt_1;
    SALT rand_salt_2;

    _generate_rand_salt(rand_salt_1);
    _generate_rand_salt(rand_salt_2);

    //Если сгенерированные соли одинаковые, то cmp = 0
    int cmp = strcmp(rand_salt_1, rand_salt_2);

    /*
    printf("rand_salt_1: ");
    _print_hex(rand_salt_1, SALT_SIZE);
    printf("rand_salt_2: ");
    _print_hex(rand_salt_2, SALT_SIZE);
    */
   
    //Если соли равны, то is_same = 1, иначе 
    int is_same = cmp == 0 ? 1 : 0;

    TEST_ASSERT_EQUAL_INT(0, is_same);
}


void test_add_zero()
{
    char non_zero [3] = {'a', 'b', 'c'};
    char zero [4] = {'a', 'b', 'c', '\0'};

    char* with_zero = _add_zero_char(non_zero, 3);

    //Если одинаковые, то cmp = 0
    int is_zero_added = strcmp(zero, with_zero);

    free(with_zero);

    TEST_ASSERT_EQUAL_INT(0, is_zero_added);
}


int main(void)
{
    UNITY_BEGIN();
    
    RUN_TEST(test_concatenation);
    RUN_TEST(test_generate_rand_salt);
    RUN_TEST(test_add_zero);

    UNITY_END();
    
    return 0;   
}