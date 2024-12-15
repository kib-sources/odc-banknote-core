/*
ODC
odc-banknote-core

Типы данных в блоках
*/
#ifndef ODC_TYPES_H
#define ODC_TYPES_H

#define VERSION_SIZE 10
#define PREFIX_SIZE 20
#define TYPE_SIZE 20
#define ID_SIZE 36
#define CODE_SIZE 9
#define APPLICABILITY_SIZE 16
#define NAME_ALGORITHM_SIZE 20
#define SIGN_SIZE 512
#define HASH_SIZE 64
#define BLOCK_TYPE_SIZE 20
#define SALT_SIZE 32

#include <openssl/evp.h>

typedef RSA* KEY;

typedef long long INT;
typedef unsigned long long UINT;

typedef char ODCB_FILE_VERSION[10];

typedef char ODCB_FILE_PREFIX[20];

typedef unsigned char BYTE;

// UUID представляет собой 16-байтный (128-битный) номер. В каноническом представлении UUID изображают
// в виде числа в шестнадцатеричной системе счисления, разделённого дефисами на пять групп в формате 8-4-4-4-12.
// Такое представление занимает 36 символов
// Например "123e4567-e89b-12d3-a456-426655440000"
// Да, мы можем сэкономить, написав char[16], но... зачем? К тому же хотелось бы сохранить какую-либо
// человекочитаемость даже в бинарных файлах (например через Editor 010)
typedef char UUID[36];


// https://ru.wikipedia.org/wiki/ISO_4217
// "RUR (810)" — российский рубль до деноминации 1998 года;
// "RUB (643)" — российский рубль после деноминации 1998 года;
// "USD (840)" — используется для общих неконкретизированных целей при совершении операций с долларами США;
typedef char CURRENCY_CODE[3+1+5];

// Количество денег в валюте CURRENCY_CODE
typedef UINT MONEY_AMOUNT;

// Указывает норму применимости передачи данной купюры
// в формате "RUS-2024-0000001".
// Данное поле позволяет заблокировать техническую возможность передачи данных
// значение "ALL-0000-0000000" обозначает отсутствие ограничений.
//
// значение "TST-..." -- это тестовые применимости.
typedef char APPLICABILITY[3+1+4+1+7];

// Путь.
// Строка с завершающим нулём.
typedef char* FILE_PATH;

// Ссылка на первый блок
// Предпоследний указатель указывает на последний блок и он должен быть BLOCK_TAIL
// Последний указатель равен 0
typedef void* BLOCKS;


// Поле, указывающее размер блока в байтах
typedef UINT BLOCK_SIZE;

// Поле комментария
typedef char COMMENT_FIELD[1024];

// Наименование алгоритма для подписи или для хеша
typedef char NAME_ALGORITHM[20];

// Подпись в байтах
typedef BYTE SIGN[512];

// Хеш в байтах
typedef BYTE HASH[64];


// Тип записываемого блока
typedef char BLOCK_TYPE[20];


// magic переменная выступающая в качестве соли для хеша

typedef BYTE SALT[SALT_SIZE];

typedef struct {
    RSA* public;
    RSA* private;
} KEYS_PAIR;

#endif /* ODC_TYPES_H */