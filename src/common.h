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
    BLOCK_HEADER* banknote,
    UUID bank_id,
    UUID banknote_id,
    CURRENCY_CODE code,
    MONEY_AMOUNT amount,
    APPLICABILITY applicability
);


void BLOCK_HEADER_sign(
    BLOCK_HEADER* banknote,
    RSA* private_key
);


// Добавить applicability новой банкноте

// Передать банкноту кошельку

// Свопнуть банкноту

// Эксчендж банкнот


// ------------------- Функции, доступные кошелькам & серверу банка ----


// Функция генерирования ключей
KEYS_PAIR _init_rsa_keys();

// Функция сохранения\загрузки ключей в\из файла

// Функция генерирования UUID
void _generate_uuid(
    UUID id
);


// Функция проверки
int _verify_signature_rsa4096(
    char* text,
    RSA* public_key,
    SIGN signature
);


// Функция SIGN
void _get_signature_rsa4096(
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
void _generate_rand_salt(
    SALT salt
);

// Функция взятия хэша
void _get_hash_sha512(
    char* text, 
    HASH hash
);


char* _add_zero_char(
    char str_without_zero[], 
    int str_size
);


void _concatenate_fields(
    char text[],
    const char* fmt, 
    ...
);


char* _int2arr(
    int number
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


void _print_uuid(
    UUID id
);


void _print_hex(
    char* arr, 
    int size
);


#endif /* ODC_SRC_COMMON_H */
