#include <stdio.h>
#include "tests.c"
RSA* bpk;
RSA* bok;
RSA* spkA;
RSA* sokA;
RSA* spkB;
RSA* sokB;

void setup_tests();

void print_hex(char* arr, int size)
{
    for (int i = 0; i < size; ++i) {
        printf("%x ", arr[i] & 0xff);
    }
    printf("\n");
}

int main()  
{
    UUID bank_id;
    generate_uuid(bank_id);
    
    UUID banknote_id;
    generate_uuid(banknote_id);
    CURRENCY_CODE code = {'U', 'S', 'D', ' ', '(', '8', '4', '0', ')'};
    MONEY_AMOUNT amount = 967293;
    //char* num = int2arr(amount);
    APPLICABILITY applicability = {'A', 'L', 'L', '-', '0', '0', '0', '0', '-', '0', '0', '0', '0', '0', '0', '0'};
    BLOCK_HEADER banknote;

    init_new_banknote(&banknote, bank_id, banknote_id, code, amount, applicability);
    printf("Amount: %d\n", banknote.amount);
    //printf("Type: %s\n", banknote.type);

    char text[500];
    
    printf("Amount2: %d\n", banknote.amount);
    concatenate_fields(text, "ududa", banknote.bank_id, ID_SIZE, banknote.banknote_id, ID_SIZE, banknote.amount);
    
    char id[ID_SIZE + 1];
    snprintf(id, ID_SIZE + 1, "%s", banknote.banknote_id);
    printf("ID: %s\n", id);

    KEYS_PAIR bk = init_rsa_keys();
    
    sign_new_banknote(&banknote, bk.private);
    

    //printf("UUID + hex: %s %x", banknote.bank_id, banknote.bank_id);
    //write_odcb_file(&banknote, "temp.odcb");
    //char* num = int2arr(banknote.amount);
    //int amount_size = sizeof(num) / sizeof(num[0]);
    //amount_size -= 1; 
    //char tt[amount_size];
    //snprintf(tt, 10, "%s", num);
    //printf("AAAAA: %s", tt);
    
    //print_uuid(bank_id);
    /*/*for (int i = 0; i < SALT_SIZE; ++i) {
        printf("%d: %d\n", i, salt[i]);
    }
    //printf("New banknote");
    CURRENCY_CODE code = {'U', 'S', 'D', ' ', '(', '8', '4', '0', ')'};
    MONEY_AMOUNT amount = 8887387;
    APPLICABILITY applicability = {'A', 'L', 'L', '-', '0', '0', '0', '0', '-', '0', '0', '0', '0', '0', '0', '0'};
    BLOCK_HEADER banknote = new_banknote_init(bank_id,
                                              banknote_id,
                                              code,
                                              amount,
                                              applicability
                                             );
    char text[20];
    snprintf(text, 20, "%s", banknote.type);
    //printf("string %s", text);
    printf("Banknote type: %s\n", text);
    printf("%s\n", banknote.bank_id);
    //snprintf(text, 1000, "%s%s%s", banknote.size, banknote.type, banknote.bank_id);
    //printf("string %s", text);
    KEYS_PAIR bk = init_rsa_keys();
    SIGN sign;

    char* plaintext = "Very very important\n";
    printf("start");
    unsigned char* enc_msg;
    char* text_base64;
    size_t enc_msg_len;
    int status;
    printf("before rsa_sign");
    rsa_sign(bk.private, plaintext, strlen(plaintext), &enc_msg, &enc_msg_len, &status);
    strcpy(sign, enc_msg);
    base64_encode(enc_msg, enc_msg_len, &text_base64);
    free(enc_msg);
    
    char* signature = sign_message(bk.private, plainText, sign);
  	char encoded[1050];*/
    
    
    

    /*KEYS_PAIR bk = init_rsa_keys();
    bpk = bk.private;
    bok = bk.public;
    KEYS_PAIR skA = init_rsa_keys();
    spkA = skA.private;
    sokA = skA.public;
    KEYS_PAIR skB = init_rsa_keys();
    spkB = skB.private;
    sokB = skB.public;*/
    //setup_tests();
    
    
    return 0;  
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