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

    char text[20];
    _concatenate_fields(text, "ssdss", name, delimiter, age, delimiter, home);
    printf("Test res: %s", text);
    char* result = "Anna;16;City";
    TEST_ASSERT_EQUAL_STRING(result, text);
}



int main(void)
{
    UNITY_BEGIN();
    
    RUN_TEST(test_concatenation);
    
    UNITY_END();
    
    return 0;   
}