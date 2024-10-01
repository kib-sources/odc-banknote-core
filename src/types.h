/*
ODC
odc-banknote-core

Типы данных в блоках
*/
#ifndef ODC_TYPES_H
#define ODC_TYPES_H

typedef INT long;
typedef UINT unsigned long;

typedef ODCB_FILE_VERSION char[10];

typedef ODCB_FILE_PREFIX char[20];

typedef BYTE unsigned char;

// UUID представляет собой 16-байтный (128-битный) номер. В каноническом представлении UUID изображают
// в виде числа в шестнадцатеричной системе счисления, разделённого дефисами на пять групп в формате 8-4-4-4-12.
// Такое представление занимает 36 символов
// Например "123e4567-e89b-12d3-a456-426655440000"
// Да, мы можем сэкономить, написав char[16], но... зачем? К тому же хотелось бы сохранить какую-либо
// человекочитаемость даже в бинарных файлах (например через Editor 010)
typedef UUID char[36];


// https://ru.wikipedia.org/wiki/ISO_4217
// "RUR (810)" — российский рубль до деноминации 1998 года;
// "RUB (643)" — российский рубль после деноминации 1998 года;
// "USD (840)" — используется для общих неконкретизированных целей при совершении операций с долларами США;
typedef CURRENCY_CODE char[3+1+5]

// Количество денег в валюте CURRENCY_CODE
typedef MONEY_AMOUNT UINT;

// Указывает норму применимости передачи данной купюры
// в формате "RUS-2024-0000001".
// Данное поле позволяет заблокировать техническую возможность передачи данных
// значение "ALL-0000-0000000" обозначает отсутствие ограничений.
typedef APPLICABILITY char[3+1+4+1+6]

// Путь.
// Строка с завершающим нулём.
typedef FILE_PATH char*;

// Ссылка на первый блок
// Предпоследний указатель указывает на последний блок и он должен быть BLOCK_TAIL
// Последний указатель равен 0
typedef BLOCKS void*;


// Поле, указывающее размер блока в байтах
typedef BLOCK_SIZE UINT;

// Поле комментария
typedef COMMENT_FIELD char[1024];

// Наименование алгоритма для подписи или для хеша
typedef NAME_ALGORITHM char[20];

// Подпись в байтах
typedef SIGN BYTE[512];

// Хеш в байтах
typedef HASH BYTE[64];


// Тип записываемого блока
typedef BLOCK_TYPE char[20];


// magic переменная выступающая в качестве соли для хеша
typedef SALT BYTE[32];

#endif /* ODC_TYPES_H */