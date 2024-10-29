#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "common.h"

/*
    type(20) + bank_id (36) + banknote_id (36) + 
    code(9) + amount(?) + applicability(16) +
    sign_algorithm(20) + hash_algorithm(20) +
    salt(32) + hash(128) + bank_sign(512)
*/
void init_new_banknote(BLOCK_HEADER* banknote, UUID bank_id, UUID banknote_id, CURRENCY_CODE code, MONEY_AMOUNT amount, APPLICABILITY applicability)
{
    
    BLOCK_TYPE type = {'h', 'e', 'a', 'd', 'e', 'r', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};
        
    int amount_size = log(amount);

    int size = 20 + 36 + 36 + 9 + amount_size + 16 +
               20 + 20 + 32 + 128 + 512;

    banknote->size = size;
    strncpy(banknote->applicability, applicability, APPLICABILITY_SIZE);
    strncpy(banknote->type, type, TYPE_SIZE);
    strncpy(banknote->bank_id, bank_id, ID_SIZE);
    strncpy(banknote->banknote_id, banknote_id, ID_SIZE);
    strncpy(banknote->code, code, CODE_SIZE);
    banknote->amount = amount;
    printf("Amount 1:: %d\n", amount);
    printf("Amount 2:: %d\n", banknote->amount);
}


void sign_new_banknote(BLOCK_HEADER* banknote, RSA* private_key)
{
    //print_uuid(banknote->bank_id);
    
    NAME_ALGORITHM hash_algorithm = {'S', 'H', 'A', '-', '5', '1', '2', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};
    
    NAME_ALGORITHM sign_algorithm = {'R', 'S', 'A', '-', '4', '0', '9', '6', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};
    
    SALT salt;
    generate_rand_salt(salt);
    //char* text;
    //snprintf(text, 20, "%s", banknote.type);
    
    strcpy(banknote->sign_algorithm, sign_algorithm);
    strcpy(banknote->hash_algorithm, hash_algorithm);
    strcpy(banknote->salt, salt);
    
    char text[500];
    concatenate_fields_for_hash(banknote, text);
    //printf("\nConcatenation: %s", text);

    HASH hash;
    get_hex_hash_sha512(&text, hash);

    strcpy(banknote->hash, hash);
    SIGN signature;
    get_signature_rsa4096(&text, private_key, signature);

}

/*
    type(20) + bank_id (36) + banknote_id (36) + 
    code(9) + amount(?) + applicability(16) +
    sign_algorithm(20) + hash_algorithm(20) +
    salt(32)
*/
void concatenate_fields_for_hash(BLOCK_HEADER* banknote, char text[500])
{
    
    int len = banknote->size - 128 - 512;
    //printf("Size: %d nd %d \n", banknote->size, len);

    char type[20];
    snprintf(type, 21, "%s", banknote->type);

    char bank_id[36];
    snprintf(bank_id, 37, "%s", banknote->bank_id);

    char banknote_id[36];
    snprintf(banknote_id, 37, "%s", banknote->banknote_id);

    char code[9];
    snprintf(code, 10, "%s", banknote->code);

    char applicability[16];
    snprintf(applicability, 17, "%s", banknote->applicability);

    char sign_algorithm[20];
    snprintf(sign_algorithm, 21, "%s", banknote->sign_algorithm);

    char hash_algorithm[20];
    snprintf(hash_algorithm, 21, "%s", banknote->hash_algorithm);

    char salt[32];
    snprintf(salt, 33, "%s", banknote->salt);


    snprintf(text, 500, "%s%s%s%s%d%s%s%s", type,
                                            bank_id,
                                            banknote_id,
                                            code,
                                            banknote->amount, 
                                            sign_algorithm,
                                            hash_algorithm,
                                            salt);

    //return &text;
}


KEYS_PAIR init_rsa_keys()
{
    
    BIGNUM* e = BN_new();
    int ret = BN_set_word(e, RSA_F4);
    
    int bits = 4096;
    RSA* rsa_key = RSA_new();
    RSA_generate_key_ex(rsa_key, bits, e, NULL); 
    BIO *bp_public  = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey (bp_public, rsa_key);
    
    BIO *bp_private = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bp_private, rsa_key, NULL, NULL, 0, NULL, NULL);

    int pri_len = BIO_pending(bp_private);
    int pub_len = BIO_pending(bp_public);
    char *pri_key = (char*) malloc(pri_len + 1);
    char *pub_key = (char*) malloc(pub_len + 1);

    BIO_read(bp_private, pri_key, pri_len); 
    BIO_read(bp_public, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    //printf("\n%s\n:\n%s\n", pri_key, pub_key);

    BIO *pb_key_bio = NULL;
    pb_key_bio = BIO_new_mem_buf((void*) pub_key, pub_len);
    BIO *prkeybio = NULL;
    prkeybio=BIO_new_mem_buf((void*) pri_key, pri_len);

    RSA *pb_rsa = NULL;
    RSA *p_rsa = NULL;

    pb_rsa = PEM_read_bio_RSAPublicKey(pb_key_bio, &pb_rsa, NULL, NULL);
    p_rsa = PEM_read_bio_RSAPrivateKey(prkeybio, &p_rsa, NULL, NULL);

    EVP_PKEY *evp_pbkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);

    EVP_PKEY *evp_prkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_prkey, p_rsa);

    free(pri_key);
    free(pub_key);
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    BIO_free(pb_key_bio);
    BIO_free(prkeybio);
    BN_free(e);
    RSA_free(rsa_key);

    KEYS_PAIR keys;
    keys.private = p_rsa;
    keys.public = pb_rsa;

    return keys;
}

//libuid
void generate_uuid(UUID id) {
    char items[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    int prev_rand = (int)time(NULL);
    
    for(int i = 0; i < 36; ++i) {
        srand(prev_rand);
        id[i] = items[rand() % 16];
        prev_rand ^= rand();
        prev_rand += id[i];
    }
    sleep(1);

    id[8] = '-';
    id[13] = '-';
    id[18] = '-';
    id[23] = '-';
}


int verify_signature_rsa4096(char* text, RSA* public_key, SIGN signature)
{
    unsigned int signature_len = RSA_size(public_key);
    unsigned char hash[SHA512_DIGEST_LENGTH];
    get_raw_hash_sha512(text, hash);
    int authentic = RSA_verify(NID_sha512, hash, SHA512_DIGEST_LENGTH, signature, &signature_len, public_key);
    return authentic;
}


void get_signature_rsa4096(char* text, RSA* private_key, SIGN signature)
{
    unsigned int signature_len = RSA_size(private_key);
    unsigned char hash[SHA512_DIGEST_LENGTH];
    get_raw_hash_sha512(text, hash);
    int res = RSA_sign(NID_sha512, hash, SHA512_DIGEST_LENGTH, signature, &signature_len, private_key);
}


void write_odcb_file(BLOCK_HEADER* banknote, FILE_PATH path)
{
    char fields[500];

    concatenate_fields_for_hash(banknote, fields);
    //printf("Fields: %s", fields);
    char hash[64];
    snprintf(hash, 65, "%s", banknote->hash);
    //printf("has: %s\n", banknote->hash);
    char signature[512];
    snprintf(signature, 512, "%s", banknote->bank_sign);

    char text[1000];
    snprintf(text, 1000, "%s%s%s", fields, hash, signature);
    //printf("Here:  %s\n", text);

    /*FILE *fp = fopen(path, "w");
    if (fp) {
        fputs(text, fp);
        fclose(fp);
        printf("File has been written\n");
    }*/
}


void generate_rand_salt(SALT salt)
{
    int prev_rand = (int)time(NULL);
    for (int i = 0; i < SALT_SIZE; ++i) {
        srand(prev_rand);
        salt[i] = rand() % 255;
        prev_rand ^= rand();
        prev_rand += salt[i];
    }
}


void get_hex_hash_sha512(char* text, HASH hash)
{
    get_raw_hash_sha512(text, hash);
}


void get_raw_hash_sha512(char* text, unsigned char hash[SHA512_DIGEST_LENGTH])
{
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, text, strlen(text));
    SHA512_Final(hash, &sha512);
}


void concatenate_fields(char text[500], const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int start = 0;
    while (*fmt != '\0') {
        if (*fmt == 'c') {
            char *temp_raw = va_arg(args, char*);
            ++fmt;

            int len = va_arg(args, int);

            char temp[len + 1];
            snprintf(temp, len + 1, "%s", temp_raw);
            
            for (int i = 0; i < len; ++i) {
                text[start+i] = temp[i];
            }

            start += len;
            //printf("text: %s\n", text);

        } else if (*fmt == 'a') {
            UINT amount_number = va_arg(args, UINT);
            printf("Amount number: %d\n", amount_number);
            //char *num = int2arr(amount_number);
            //int amount_size = sizeof(num) / sizeof(num[0]);

            //int n = log10(*amount_number) + 1;
            //printf("Size4: %d\n", n);

        }
        ++fmt;
    }
 
    va_end(args);
}


void print_uuid(UUID id)
{
    char text[36];
    snprintf(text, 37, "%s", id);
    printf("UUID: %s", text);
}

