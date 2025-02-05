#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <uuid/uuid.h>
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
void BLOCK_HEADER_init(BLOCK_HEADER *banknote, UUID bank_id, UUID banknote_id, CURRENCY_CODE code, MONEY_AMOUNT amount, APPLICABILITY applicability, UUID owner_id)
{
    
    BLOCK_TYPE type = {'h', 'e', 'a', 'd', 'e', 'r', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};
        
    int amount_size = log(amount);

    int size = TYPE_SIZE + ID_SIZE + ID_SIZE + CODE_SIZE + amount_size + APPLICABILITY_SIZE +
               NAME_ALGORITHM_SIZE + NAME_ALGORITHM_SIZE + SALT_SIZE + HASH_SIZE + SIGN_SIZE + KEY_SIZE + ID_SIZE;

    banknote->size = size;
    banknote->count_append_applicability_blocks = 0;
    strncpy(banknote->applicability, applicability, APPLICABILITY_SIZE);
    strncpy(banknote->type, type, TYPE_SIZE);
    strncpy(banknote->bin, bank_id, ID_SIZE);
    strncpy(banknote->bnid, banknote_id, ID_SIZE);
    strncpy(banknote->owner, owner_id, ID_SIZE);
    strncpy(banknote->code, code, CODE_SIZE);
    banknote->amount = amount;
}


/*
    Заполняем оставшиеся поля + вычисление хэша + подпись
*/
void BLOCK_HEADER_sign(BLOCK_HEADER *banknote, KEYS_PAIR rsa_pem_keys)
{    
    NAME_ALGORITHM hash_algorithm = {'S', 'H', 'A', '-', '5', '1', '2', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};
    
    NAME_ALGORITHM sign_algorithm = {'R', 'S', 'A', '-', '4', '0', '9', '6', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'};
    
    SALT salt;
    _generate_rand_salt(salt);

    strncpy(banknote->sign_algorithm, sign_algorithm, NAME_ALGORITHM_SIZE);
    strncpy(banknote->hash_algorithm, hash_algorithm, NAME_ALGORITHM_SIZE);
    strncpy(banknote->salt, salt, SALT_SIZE);
    banknote->bok = rsa_pem_keys.public;

    char *concatenated_text = BLOCK_HEADER_concatenate_fields_for_hash(banknote);

    HASH hash;
    _get_hash_sha512(concatenated_text, hash);

    strncpy(banknote->hash, hash, HASH_SIZE);

    SIGN signature;
    RSA *private_key = pem_to_rsa_private_key(rsa_pem_keys.private.pem_key);

    _get_signature_rsa4096(concatenated_text, private_key, signature);
    
    for (int i = 0; i < SIGN_SIZE; ++i) {
        banknote->bank_sign[i] = signature[i];
    }

    free(concatenated_text);
}


int BLOCK_HEADER_verify(BLOCK_HEADER *banknote)
{
    RSA *public_rsa = pem_to_rsa_public_key(banknote->bok.pem_key);

    char *plain_text = BLOCK_HEADER_concatenate_fields_for_hash(banknote);

    SIGN sign;
    for (int i = 0; i < SIGN_SIZE; ++i) {
        sign[i] = banknote->bank_sign[i];
    }

    int verify_status = _verify_signature_rsa4096(plain_text, public_rsa, sign);
   
    RSA_free(public_rsa);

    return verify_status;
}


KEYS_PAIR _init_rsa_keys()
{
    BIGNUM *e = BN_new();
    int ret = BN_set_word(e, RSA_F4);
    
    int bits = 4096;
    RSA *rsa_key = RSA_new();
    RSA_generate_key_ex(rsa_key, bits, e, NULL); 
    
    BIO *bio_private = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_private, rsa_key, NULL, NULL, 0, NULL, NULL);

    int private_key_pem_len = BIO_pending(bio_private);

    char *private_key_pem = (char *)calloc(private_key_pem_len + 1, sizeof(char));
    BIO_read(bio_private, private_key_pem, private_key_pem_len); 
    private_key_pem[private_key_pem_len] = '\0';


    BIGNUM *n = NULL;
    e = NULL;
    RSA_get0_key(rsa_key, &n, &e, NULL);

    RSA *public_key = RSA_new();
    RSA_set0_key(public_key, BN_dup(n), BN_dup(e), NULL);

    BIO *bio_public = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio_public, public_key);

    int public_key_pem_len = BIO_pending(bio_public);

    char *public_key_pem = (char *)calloc(public_key_pem_len + 1, sizeof(char));
    BIO_read(bio_public, public_key_pem, public_key_pem_len); 
    public_key_pem[public_key_pem_len] = '\0';

    //printf("%d\n %d\n", private_key_pem_len, public_key_pem_len);


    PEM_KEY pem_pr_key;
    pem_pr_key.pem_key = private_key_pem;
    pem_pr_key.len = private_key_pem_len;
    PEM_KEY pem_pb_key;
    pem_pb_key.pem_key = public_key_pem;
    pem_pb_key.len = public_key_pem_len;

    KEYS_PAIR rsa_pair;
    rsa_pair.private = pem_pr_key;
    rsa_pair.public = pem_pb_key;
    //printf("%d\n %d\n", rsa_pair.private.len, rsa_pair.public.len);
    //printf("%s\n %s\n", rsa_pair.private.pem_key, rsa_pair.public.pem_key);

    BIO_free_all(bio_public);
    BIO_free_all(bio_private);
    BN_free(e);
    BN_free(n);

    return rsa_pair;
}


RSA *pem_to_rsa_private_key(char *pem_key)
{
    BIO *bio = BIO_new_mem_buf((void *)pem_key, -1);
    
    RSA *rsa = NULL;
    rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);  
    
    BIO_free(bio);

    return rsa;
}


RSA *pem_to_rsa_public_key(char *pem_key)
{
    BIO *bio = BIO_new_mem_buf((void*)pem_key, -1);
    
    //Для -----BEGIN RSA PUBLIC KEY-----
    //RSA *rsa = NULL;
    //rsa = PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);  
    
    //Для -----BEGIN PUBLIC KEY-----
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    BIO_free(bio);

    return rsa;
}


void _generate_uuid(UUID id) {
    /*char items[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

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
    id[23] = '-';*/

    uuid_t uuid;

    uuid_generate(uuid);

    uuid_unparse(uuid, id);

    //printf("Generated UUID: %s\n", id);
}


int _verify_signature_rsa4096(char *text, RSA *public_key, SIGN signature)
{
    unsigned int signature_len = SIGN_SIZE;
    
    HASH hash;
    _get_hash_sha512(text, hash);

    int authentic = RSA_verify(NID_sha512, hash, SHA512_DIGEST_LENGTH, signature, signature_len, public_key);
    
    return authentic;
}


void _get_signature_rsa4096(char *text, RSA *private_key, SIGN signature)
{
    unsigned int signature_len = 0;
    
    HASH hash;
    _get_hash_sha512(text, hash);
    
    int res = RSA_sign(NID_sha512, hash, SHA512_DIGEST_LENGTH, signature, (unsigned int *)&signature_len, private_key);
}


void write_odcb_file(BLOCK_HEADER *banknote, FILE_PATH path)
{
    char *concatenated_fields = BLOCK_HEADER_concatenate_all_fields(banknote);

    FILE *fp = fopen(path, "w");

    if (fp) {
        fputs(concatenated_fields, fp);
        fclose(fp);
        printf("File has been written\n");
    }

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


void _get_hash_sha512(char *text, HASH hash)
{
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, text, strlen(text));
    SHA512_Final(hash, &sha512);
}

/*
    Возвращает null terminated строку, необходимо для конкатенации
*/
char *_add_zero_char(char str_without_zero[], int str_size)
{
    char *str_with_zero = (char *)malloc((str_size + 1) * sizeof(char));
    
    for (int i = 0; i < str_size; ++i) {
        str_with_zero[i] = str_without_zero[i];
    }
    
    str_with_zero[str_size] = '\0';

    return str_with_zero;
}

/*
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
char *BLOCK_HEADER_concatenate_fields_for_hash(BLOCK_HEADER *banknote)
{
    char *type_c_str = _add_zero_char(banknote->type, TYPE_SIZE);
    char *bank_id_c_str = _add_zero_char(banknote->bin, ID_SIZE);
    char *banknote_id_c_str = _add_zero_char(banknote->bnid, ID_SIZE);
    char *owner_id_c_str = _add_zero_char(banknote->owner, ID_SIZE);
    char *code_c_str = _add_zero_char(banknote->code, CODE_SIZE);
    char *applicability_c_str = _add_zero_char(banknote->applicability, APPLICABILITY_SIZE);
    char *sign_algorithm_c_str = _add_zero_char(banknote->sign_algorithm, NAME_ALGORITHM_SIZE);
    char *hash_algorithm_c_str = _add_zero_char(banknote->hash_algorithm, NAME_ALGORITHM_SIZE);
    char *salt_c_str = _add_zero_char(banknote->salt, SALT_SIZE);

    char *concatenated_text = _concatenate_fields("sssssddssss", type_c_str,
                                                          bank_id_c_str,
                                                          banknote_id_c_str,
                                                          owner_id_c_str,
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
    free(owner_id_c_str);
    free(code_c_str);
    free(applicability_c_str);
    free(sign_algorithm_c_str);
    free(hash_algorithm_c_str);
    free(salt_c_str);


    return concatenated_text;
}


char *BLOCK_HEADER_concatenate_all_fields(BLOCK_HEADER *banknote)
{
    char *delimiter = ".";

    size_t size_size = (banknote->size == 0) ? 1 : log10(banknote->size) + 1;

    char *type_c_str = _add_zero_char(banknote->type, TYPE_SIZE);
    char *bank_id_c_str = _add_zero_char(banknote->bin, ID_SIZE);
    char *banknote_id_c_str = _add_zero_char(banknote->bnid, ID_SIZE);
    char *owner_id_c_str = _add_zero_char(banknote->owner, ID_SIZE);
    char *code_c_str = _add_zero_char(banknote->code, CODE_SIZE);

    size_t amount_size = (banknote->amount == 0) ? 1 : log10(banknote->amount) + 1;

    char *applicability_c_str = _add_zero_char(banknote->applicability, APPLICABILITY_SIZE);

    size_t count_size = (banknote->count_append_applicability_blocks == 0) ? 1 : log10(banknote->count_append_applicability_blocks) + 1;

    char *sign_algorithm_c_str = _add_zero_char(banknote->sign_algorithm, NAME_ALGORITHM_SIZE);
    char *hash_algorithm_c_str = _add_zero_char(banknote->hash_algorithm, NAME_ALGORITHM_SIZE);
    //char *salt_c_str = _add_zero_char(banknote->salt, SALT_SIZE);

    size_t salt_base64_size;
    char *salt_base64_c_str = _bytes_2_base64(banknote->salt, SALT_SIZE, &salt_base64_size);
    char *salt_hex = _bytes_2_hex(banknote->salt, HASH_SIZE);
    printf("salt hex: %s\n", salt_hex);
    printf("salt base64: %s\n", salt_base64_c_str);

    char *hash_hex = _bytes_2_hex(banknote->hash, HASH_SIZE);
    printf("Hash hex: %s\n", hash_hex);
    size_t hash_base64_size;
    char *hash_base64_c_str = _bytes_2_base64(banknote->hash, HASH_SIZE, &hash_base64_size);
    printf("Hash base64: %s\n", hash_base64_c_str);

    char *sign_hex = _bytes_2_hex(banknote->bank_sign, SIGN_SIZE);
    printf("sign hex: %s\n", sign_hex);
    size_t sign_base64_size;
    char *sign_base64_c_str = _bytes_2_base64(banknote->bank_sign, SIGN_SIZE, &sign_base64_size);
    printf("sign base64: %s\n", sign_base64_c_str);

    char *concatenated_fields = _concatenate_fields("dsd dss dss dss dss dss dsd dss dsd dss dss dss dss dss dss",
                                                    size_size, delimiter, banknote->size,
                                                    TYPE_SIZE, delimiter, type_c_str,
                                                    ID_SIZE, delimiter, bank_id_c_str,
                                                    ID_SIZE, delimiter, banknote_id_c_str,
                                                    ID_SIZE, delimiter, owner_id_c_str,
                                                    CODE_SIZE, delimiter, code_c_str,
                                                    amount_size, delimiter, banknote->amount,
                                                    APPLICABILITY_SIZE, delimiter, applicability_c_str,
                                                    count_size, delimiter, banknote->count_append_applicability_blocks,
                                                    NAME_ALGORITHM_SIZE, delimiter, sign_algorithm_c_str,
                                                    NAME_ALGORITHM_SIZE, delimiter, hash_algorithm_c_str,
                                                    salt_base64_size, delimiter, salt_base64_c_str,
                                                    hash_base64_size, delimiter, hash_base64_c_str,
                                                    banknote->bok.len, delimiter, banknote->bok.pem_key,
                                                    sign_base64_size, delimiter, sign_base64_c_str);

    free(type_c_str);
    free(bank_id_c_str);
    free(banknote_id_c_str);
    free(owner_id_c_str);
    free(code_c_str);
    free(applicability_c_str);
    free(sign_algorithm_c_str);
    free(hash_algorithm_c_str);
    free(salt_base64_c_str);
    free(hash_base64_c_str);
    free(sign_base64_c_str);


    return concatenated_fields;
}


char *_concatenate_fields(const char *fmt, ...)
{
    char *ptr = (char *)calloc(1000, sizeof(char));

    va_list args;
    va_start(args, fmt);

    int ind_start = 0;

    while (*fmt != '\0') {
        if (*fmt == 's') {
            char *temp_raw = va_arg(args, char *);
            
            int len = strlen(temp_raw);
            if (ind_start + len >= 1000) {
                ptr = (char *)realloc(ptr, ind_start + len + 1);
            }
            for (int i = 0; i < len; ++i) {
                
                ptr[ind_start + i] = temp_raw[i];
            }

            ind_start += len;
        } else if (*fmt == 'd') {
            int amount_number = va_arg(args, int);

            char *num = _int_2_arr(amount_number);
            int len = strlen(num);

            if (ind_start + len >= 1000) {
                ptr = (char *)realloc(ptr, ind_start + len + 1);
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


void _hex_2_bytes(char *hex_str, BYTE *bytes, int size)
{
    for (int i = 0; i < size; i++) {
        char temp[3] = {hex_str[i * 2], hex_str[i * 2 + 1], '\0'};
        bytes[i] = (unsigned char)strtol(temp, NULL, 16); 
    }
}


unsigned char *_bytes_2_hex(BYTE* bytes, int size)
{
    unsigned char *hex_str = calloc(size * 2, sizeof(unsigned char));
    
    for(int i = 0; i < size; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }

    return hex_str;
}


unsigned char _decode_base64_char(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return 255; 
}


BYTE * _base64_2_bytes(char *base64_str, size_t *decoded_len)
{
    size_t len = strlen(base64_str);
    //printf("Len: %d\n", len);

    if (len % 4 != 0) {
        printf("Invalid Base64 string length.\n");
        return NULL;
    }

    size_t padding = 0;
    if (len >= 2 && base64_str[len - 1] == '=') {
        padding++;
    }
    if (len >= 3 && base64_str[len - 2] == '=') {
        padding++;
    }

    *decoded_len = (len / 4) * 3 - padding;

    BYTE *decoded = calloc(*decoded_len, sizeof(BYTE *));
    size_t j = 0;
    for (size_t i = 0; i < len; i += 4) {
        uint32_t sextet = (_decode_base64_char(base64_str[i]) << 18) |
                          (_decode_base64_char(base64_str[i + 1]) << 12) |
                          (_decode_base64_char(base64_str[i + 2]) << 6) |
                          _decode_base64_char(base64_str[i + 3]);
        if (j < *decoded_len) decoded[j++] = (sextet >> 16) & 0xFF;
        if (j < *decoded_len) decoded[j++] = (sextet >> 8) & 0xFF;
        if (j < *decoded_len) decoded[j++] = sextet & 0xFF;
    }

    return decoded;
}


char *_bytes_2_base64(BYTE *data, size_t decoded_len, size_t *encoded_len) 
{

    static char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static int mod_table[] = {0, 2, 1};

    *encoded_len = ((decoded_len + 2) / 3) * 4;

    
    char *encoded_data = malloc(*encoded_len);
    if (encoded_data == NULL) {
        return NULL;
    }

    for (int i = 0, j = 0; i < decoded_len;) {
        uint32_t octet_a = i < decoded_len ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < decoded_len ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < decoded_len ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[decoded_len % 3]; i++) {
        encoded_data[*encoded_len - 1 - i] = '=';
    }

    return encoded_data;
}


char *_extract_base64_from_pem(char *pem_key)
{
    char *begin = strchr(pem_key, '\n');
    char *end = strchr(begin, '-');

    int begin_index = (int)(begin - pem_key);
    int end_index = (int)(end - pem_key);
    int suggested_size = end_index - begin_index;

    char *stripped_pem_key = (char *)calloc(suggested_size, sizeof(char));

    int shift = 0;
    for (int i = 0; i < suggested_size; ++i) {
        if (pem_key[begin_index + i] == '\n') {
            shift += 1;
        } else {
            stripped_pem_key[i - shift] = pem_key[begin_index + i];
        }

    }

    int actual_size = suggested_size - shift;

    //printf("Suggested size: %d\nActual size: %d\n", suggested_size, actual_size);

    //printf("Striped: %s\n", stripped_pem_key);

    stripped_pem_key = (char *)realloc(stripped_pem_key, actual_size);

    return stripped_pem_key;
}


BYTE *_pem_2_bytes(char *pem_key, size_t *bytes_key_size) 
{
    char *base64_key = _extract_base64_from_pem(pem_key);

    BYTE *bytes_key = _base64_2_bytes(base64_key, bytes_key_size);

    free(base64_key);

    return bytes_key;
}

//0 - private, 1 - puiblic
char *_bytes_2_pem(BYTE *bytes_key, size_t bytes_key_size, size_t *pem_key_size, unsigned char pem_type)
{
    char *base64 = _bytes_2_base64(bytes_key, bytes_key_size, pem_key_size);    
    
    int base64_len = *pem_key_size;
    
    char *first_pem_line;
    char *last_pem_line;
    if (pem_type == 0) {
        first_pem_line = "-----BEGIN RSA PRIVATE KEY-----\n";
        last_pem_line = "-----END RSA PRIVATE KEY-----\n";
    } else {
        first_pem_line = "-----BEGIN PUBLIC KEY-----\n";
        last_pem_line = "-----END PUBLIC KEY-----\n";
    }

    int delimeters = strlen(base64) / 63;

    *pem_key_size = base64_len + delimeters + strlen(first_pem_line) + strlen(last_pem_line) + 1;
    //printf("Len: %d\n", *pem_key_size);
    char *pem_key = (char*)calloc(*pem_key_size, sizeof(char));

    for (int i = 0; i < strlen(first_pem_line); ++i) {
        pem_key[i] = first_pem_line[i];
    }

    int ind = strlen(first_pem_line);

    for (int i = 0; i < base64_len; ++i) {
        if (i % 64 == 0 && i != 0) {
            pem_key[ind] = '\n';
            ind += 1;
        }
        pem_key[ind] = base64[i];
        ind += 1;
    }


    if (pem_key[ind - 1] != '\n') {
        pem_key[ind] = '\n';
        ind += 1;
    }

    for (int i = 0; i < strlen(last_pem_line); ++i) {
        pem_key[ind] = last_pem_line[i];
        ind += 1;
    }

    free(base64);

    return pem_key;
}


void _print_uuid(UUID id)
{
    char text[37];
    snprintf(text, 37, "%s", id);
    printf("UUID: %s", text);
}


char *_int_2_arr(int number)
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


void _print_hex(BYTE *bytes, int size)
{ 
    printf("Raw format: ");

    for (int i = 0; i < size; ++i) {
        printf("%x ", bytes[i] & 0xff);
    }

    printf("\n");
}


void _print_banknote_header(BLOCK_HEADER *banknote)
{
    printf("Size:\n");
    printf("\t%d\n", banknote->size);

    printf("Type:\n");
    char *b_type = _add_zero_char(banknote->type, TYPE_SIZE);
    printf("\t%s\n", b_type);

    printf("Bin:\n");
    char *b_bin = _add_zero_char(banknote->bin, ID_SIZE);
    printf("\t%s\n", b_bin);

    printf("Bnid:\n");
    char *b_bnid = _add_zero_char(banknote->bnid, ID_SIZE);
    printf("\t%s\n", b_bnid);

    printf("Owner:\n");
    char *b_owner = _add_zero_char(banknote->owner, ID_SIZE);
    printf("\t%s\n", b_owner);

    printf("Code:\n");
    char *b_code = _add_zero_char(banknote->code, CODE_SIZE);
    printf("\t%s\n", b_code);

    printf("Amount:\n");
    printf("\t%d\n", banknote->amount);

    printf("Applicability:\n");
    char *b_applicability = _add_zero_char(banknote->applicability, APPLICABILITY_SIZE);
    printf("\t%s\n", b_applicability);
    
    printf("Count_append_applicability_blocks:\n");
    printf("\t%d\n", banknote->count_append_applicability_blocks);

    printf("Sign_algorithm:\n");
    char *b_sign_algorithm = _add_zero_char(banknote->sign_algorithm, NAME_ALGORITHM_SIZE);
    printf("\t%s\n", b_sign_algorithm);

    printf("Hash_algorithm:\n");
    char *b_hash_algorithm = _add_zero_char(banknote->hash_algorithm, NAME_ALGORITHM_SIZE);
    printf("\t%s\n", b_hash_algorithm);

    printf("Salt:\n\t");
    _print_hex(banknote->salt, SALT_SIZE);

    printf("Hash:\n\t");
    _print_hex(banknote->hash, HASH_SIZE);

    printf("Bank_sign:\n\t");
    _print_hex(banknote->bank_sign, SIGN_SIZE);

    printf("Bok:\n");
    printf("%s\n", banknote->bok);
}