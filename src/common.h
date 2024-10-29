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
// Разделить нициирование (new_banknote_init) + подпись(new_banknote_sign)
void init_new_banknote (
    BLOCK_HEADER* banknote,
    UUID bank_id,
    UUID banknote_id,
    CURRENCY_CODE code,
    MONEY_AMOUNT amount,
    APPLICABILITY applicability
);

void sign_new_banknote (
    BLOCK_HEADER* banknote,
    RSA* private_key
);

void concatenate_fields_for_hash(
    BLOCK_HEADER* banknote,
    char text[500]
);



// Добавить applicability новой банкноте

// Передать банкноту кошельку

// Свопнуть банкноту

// Эксчендж банкнот


// ------------------- Функции, доступные кошелькам & серверу банка ----


// Функция генерирования ключей
KEYS_PAIR init_rsa_keys();

// Функция сохранения\загрузки ключей в\из файла

// Функция генерирования UUID
void generate_uuid(
    UUID id
);

// Функция проверки
int verify_signature_rsa4096(
    char* text,
    RSA* public_key,
    SIGN signature
);


// Функция SIGN
void get_signature_rsa4096(
    char* text,
    RSA* private_key,
    SIGN signature
);


// Функции по передаче банкноты

// Функции по проверке подлинности банкноты (без или со свопом)

// Запись в файл структуры данных
void write_odcb_file(
    //BANKNOTE_ODCB banknote,
    BLOCK_HEADER* banknote,
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

// Функция генерации рандомной соли
void generate_rand_salt(
    SALT salt
);

// Функция хэша
void get_hex_hash_sha512(
    char* text, 
    HASH hash
);

void get_raw_hash_sha512(
    char* text, 
    unsigned char hash[SHA512_DIGEST_LENGTH]
);

void concatenate_fields(
    char text[500],
    const char* fmt, 
    ...
);


// ----------------------- Удобные дополнительные функции для отладки и сериализации --------------------------------


// *.odcb файл переводит в *.json
void odcb2json(
    FILE_PATH path_odcb,
    FILE_PATH path_json,
    int indent
    // ... TODO продумать какие ещё поля
);


// *.json переводит в *.odcb
void json2odcb(
    FILE_PATH path_odcb,
    FILE_PATH path_json
);


void print_uuid(
    UUID id
);


#endif /* ODC_SRC_COMMON_H */
