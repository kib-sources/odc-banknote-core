/*
ODC
odc-banknote-core

Общие функции
*/
#ifndef ODC_SRC_COMMON_H
#define ODC_SRC_COMMON_H
#include <stdarg.h>
#include "banknote_blocks.h"
#include "banknote.h"




// ------------------- Функции, доступные серверу банка ----------------

// Новая банкнота
// Разделить инициирование (new_banknote_init) + подпись(new_banknote_sign)
void BLOCK_HEADER_init(
    BLOCK_HEADER *banknote,
    UUID bank_id,
    UUID banknote_id,
    CURRENCY_CODE code,
    MONEY_AMOUNT amount,
    APPLICABILITY applicability,
    UUID owner_id
);


void BLOCK_HEADER_sign(
    BLOCK_HEADER *banknote,
    KEYS_PAIR rsa_pem_keys
);

//1 - подпись валидна
int BLOCK_HEADER_verify(
    BLOCK_HEADER *banknote
);
// Добавить applicability новой банкноте

// Передать банкноту кошельку

// Свопнуть банкноту

// Эксчендж банкнот


// ------------------- Функции, доступные кошелькам & серверу банка ----


// Функция генерирования ключей
void initialize_randomness();
KEYS_PAIR _init_rsa_keys();

// Функции сохранения\загрузки ключей в\из файла

// Функции конвертации ключей
RSA *pem_to_rsa_private_key(
    char *pem_key
);


RSA *pem_to_rsa_public_key(
    char *pem_key
);


// Функция генерирования UUID
void _generate_uuid(
    UUID id
);


// Функция проверки
int _verify_signature_rsa4096(
    char *text,
    RSA *public_key,
    SIGN signature
);


// Функция подписи
void _get_signature_rsa4096(
    char *text,
    RSA *private_key,
    SIGN signature
);


// Функции по передаче банкноты

// Функции по проверке подлинности банкноты (без или со свопом)

// Запись в файл структуры данных
void write_odcb_file(
    //BANKNOTE_ODCB banknote,
    BLOCK_HEADER *banknote,
    FILE_PATH path
);

// Функция, выдающая количество блоков
UINT count_blocks(
    BANKNOTE_ODCB banknote
);

// Чтение odcb файла
BANKNOTE_ODCB read_odcb_file(
    FILE_PATH path
);


unsigned int _produce_random_byte();

// Функция генерации рандомной соли
void _generate_rand_salt(
    SALT salt
);

// Функция взятия хэша
void _get_hash_sha512(
    char *text, 
    HASH hash
);


char *_add_zero_char(
    char str_without_zero[], 
    int str_size
);


char *BLOCK_HEADER_concatenate_fields_for_hash(
    BLOCK_HEADER *banknote
);


char *BLOCK_HEADER_concatenate_all_fields(
    BLOCK_HEADER *banknote
);


char *_concatenate_fields(
    const char *fmt, 
    ...
);


char *_int_2_arr(
    int number
);



// ----------------------- Удобные дополнительные функции для отладки и сериализации --------------------------------

// *.odcb файл переводит в *.json
void odcb_2_json(
    FILE_PATH path_odcb,
    FILE_PATH path_json,
    int indent
    // ... TODO продумать какие ещё поля
);

// *.json переводит в *.odcb
void json_2_odcb(
    FILE_PATH path_odcb,
    FILE_PATH path_json
);


//Конвертация представления 16-ой строки в массив байтов

void _hex_2_bytes(
    char *hex_str, 
    BYTE *bytes,
    int size
);


unsigned char *_bytes_2_hex( 
    BYTE *bytes,
    int size
);


//Конвертация строки в кодировке base64 в массив байтов

unsigned char _decode_base64_char(
    char c
);


BYTE *_base64_2_bytes(
    char *base64_str, 
    size_t *decoded_len
);


char *_bytes_2_base64(
    BYTE *bytes,
    size_t decoded_len,
    size_t *encoded_len
);


//Конвертация pem предсталения ключа RSA в массив байтов
char *_extract_base64_from_pem(
    char *pem_key
);

BYTE *_pem_2_bytes(
    char *pem_key, 
    size_t *bytes_key_size
);


char *_bytes_2_pem(
    BYTE *bytes_key, 
    size_t bytes_key_size, 
    size_t *pem_key_size, 
    unsigned char pem_type
);


//Функции вывода

void _print_uuid(
    UUID id
);


void _print_hex(
    BYTE *bytes, 
    int size
);


void _print_banknote_header(
    BLOCK_HEADER *banknote
);


#endif /* ODC_SRC_COMMON_H */
