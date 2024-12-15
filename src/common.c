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
    Здесь инициируем только первые поля (не все)
    Рассчет размера:
    type(20) + bank_id (36) + banknote_id (36) + 
    code(9) + amount(?) + applicability(16) +
    sign_algorithm(20) + hash_algorithm(20) +
    salt(32) + hash(128) + bank_sign(512)
*/
void BLOCK_HEADER_init(BLOCK_HEADER* banknote, UUID bank_id, UUID banknote_id, CURRENCY_CODE code, MONEY_AMOUNT amount, APPLICABILITY applicability)
{
    
    BLOCK_TYPE type = {'h', 'e', 'a', 'd', 'e', 'r', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};
        
    int amount_size = log(amount);

    int size = 20 + 36 + 36 + 9 + amount_size + 16 +
               20 + 20 + 32 + 128 + 512;

    banknote->size = size;
    banknote->count_append_applicability_blocks = 0;
    strncpy(banknote->applicability, applicability, APPLICABILITY_SIZE);
    strncpy(banknote->type, type, TYPE_SIZE);
    strncpy(banknote->bin, bank_id, ID_SIZE);
    strncpy(banknote->bnid, banknote_id, ID_SIZE);
    strncpy(banknote->code, code, CODE_SIZE);
    banknote->amount = amount;
}


/*
    Заполняем оставшиеся поля + вычисление хэша + подпись
    Для хэша конкатенируем следующие поля:
        type
        bin
        bnid
        code
        amount
        applicability
        count_append_applicability_blocks
        sign_algorithm
        hash_algorithm
        salt
*/
void BLOCK_HEADER_sign(BLOCK_HEADER* banknote, RSA* private_key)
{    
    NAME_ALGORITHM hash_algorithm = {'S', 'H', 'A', '-', '5', '1', '2', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};
    
    NAME_ALGORITHM sign_algorithm = {'R', 'S', 'A', '-', '4', '0', '9', '6', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};
    
    SALT salt;
    _generate_rand_salt(salt);
    
    strcpy(banknote->sign_algorithm, sign_algorithm);
    strcpy(banknote->hash_algorithm, hash_algorithm);
    strcpy(banknote->salt, salt);
    
    
    
    char *type_c_str = _add_zero_char(banknote->type, TYPE_SIZE);
    char *bank_id_c_str = _add_zero_char(banknote->bin, ID_SIZE);
    char *banknote_id_c_str = _add_zero_char(banknote->bnid, ID_SIZE);
    char *code_c_str = _add_zero_char(banknote->code, CODE_SIZE);
    char *applicability_c_str = _add_zero_char(banknote->applicability, APPLICABILITY_SIZE);
    char *sign_algorithm_c_str = _add_zero_char(banknote->sign_algorithm, NAME_ALGORITHM_SIZE);
    char *hash_algorithm_c_str = _add_zero_char(banknote->hash_algorithm, NAME_ALGORITHM_SIZE);
    char *salt_c_str = _add_zero_char(banknote->salt, SALT_SIZE);

    char* concatenated_text = _concatenate_fields("ssssddssss", type_c_str,
                                                                bank_id_c_str,
                                                                banknote_id_c_str,
                                                                code_c_str,
                                                                banknote->amount,
                                                                banknote->count_append_applicability_blocks,
                                                                applicability_c_str,
                                                                sign_algorithm_c_str,
                                                                hash_algorithm_c_str,
                                                                salt_c_str);
    

    free(type_c_str);
    free(bank_id_c_str);
    free(banknote_id_c_str);
    free(code_c_str);
    free(applicability_c_str);
    free(sign_algorithm_c_str);
    free(hash_algorithm_c_str);
    free(salt_c_str);

    //printf("\nConcatenation: %s", text);

    HASH hash;
    _get_hash_sha512(&concatenated_text, hash);

    strcpy(banknote->hash, hash);
    strncpy(banknote->hash, hash, HASH_SIZE);

    SIGN signature;
    _get_signature_rsa4096(&concatenated_text, private_key, signature);

    free(concatenated_text);
}


KEYS_PAIR _init_rsa_keys()
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
void _generate_uuid(UUID id) {
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


int _verify_signature_rsa4096(char* text, RSA* public_key, SIGN signature)
{
    unsigned int signature_len = RSA_size(public_key);
    unsigned char hash[SHA512_DIGEST_LENGTH];
    _get_hash_sha512(text, hash);
    int authentic = RSA_verify(NID_sha512, hash, SHA512_DIGEST_LENGTH, signature, &signature_len, public_key);
    return authentic;
}


void _get_signature_rsa4096(char* text, RSA* private_key, SIGN signature)
{
    unsigned int signature_len = RSA_size(private_key);
    unsigned char hash[SHA512_DIGEST_LENGTH];
    _get_hash_sha512(text, hash);
    int res = RSA_sign(NID_sha512, hash, SHA512_DIGEST_LENGTH, signature, &signature_len, private_key);
}


void write_odcb_file(BLOCK_HEADER* banknote, FILE_PATH path)
{

}


unsigned int _produce_random_byte() {
    union {
        unsigned int i;
        unsigned char c[sizeof(unsigned int)];
    } u;

    int limit = 255;

    do {
        if (!RAND_bytes(u.c, sizeof(u.c))) {
            fprintf(stderr, "Can't get random bytes!\n");
            exit(1);
        }
    } while (u.i < (-limit % limit)); 
    return u.i % limit;
}


void _generate_rand_salt(SALT salt)
{
    for (int i = 0; i < SALT_SIZE; ++i) {
        salt[i] = _produce_random_byte();
    }
}


void _get_hash_sha512(char* text, HASH hash)
{
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, text, strlen(text));
    SHA512_Final(hash, &sha512);
}

/*
    Возвращает null terminated строку, необходимо для конкатенации
*/
char* _add_zero_char(char str_without_zero[], int str_size)
{
    char *str_with_zero = (char*)malloc((str_size + 1) * sizeof(char));
    
    for (int i = 0; i < str_size; ++i) {
        str_with_zero[i] = str_without_zero[i];
    }
    
    str_with_zero[str_size] = '\0';

    return str_with_zero;
}


char* _concatenate_fields(const char* fmt, ...)
{
    char *ptr = (char *)calloc(1000, sizeof(char));

    va_list args;
    va_start(args, fmt);

    int ind_start = 0;

    while (*fmt != '\0') {
        if (*fmt == 's') {
            char *temp_raw = va_arg(args, char*);
            
            int len = strlen(temp_raw);
            if (ind_start >= 1000) {
                ptr = (char *)realloc(ptr, ind_start + 100);
            }
            for (int i = 0; i < len; ++i) {
                
                ptr[ind_start + i] = temp_raw[i];
            }

            ind_start += len;
        } else if (*fmt == 'd') {
            int amount_number = va_arg(args, int);

            char *num = _int2arr(amount_number);
            int len = strlen(num);

            if (ind_start >= 1000) {
                ptr = (char *)realloc(ptr, ind_start + 100);
            }
            for (int i = 0; i < len; ++i) {
                ptr[ind_start + i] = num[i];
            }
            free(num);

            ind_start += len;
        }
        ++fmt;
    }

    ptr = (char *)realloc(ptr, ind_start + 1);
    ptr[ind_start] = '\0';
 
    va_end(args);

    return ptr;
}


void _print_uuid(UUID id)
{
    char text[36];
    snprintf(text, 37, "%s", id);
    printf("UUID: %s", text);
}


char* _int2arr(int number)
{
    if (number == 0) {
        char *digits = calloc(1, sizeof(char));
        digits[0] = '0';
        return digits;
    }
    int n = log10(number) + 1;
    int i;
    char *digits = calloc(n, sizeof(char));
    for (i = n-1; i >= 0; --i, number /= 10) {
        digits[i] = (number % 10) + '0';
    }
    return digits;
}


void _print_hex(char* arr, int size)
{ 
    printf("Raw format: ");

    for (int i = 0; i < size; ++i) {
        printf("%x ", arr[i] & 0xff);
    }

    printf("\n");
}
