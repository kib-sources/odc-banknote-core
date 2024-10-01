/*
ODC
odc-banknote-core

Общие функции
*/
#ifndef ODC_SRC_COMMON_H
#define ODC_SRC_COMMON_H

#include "types.h"
#include "banknote.h"


// ------------------- Функции, доступные серверу банка ----------------

// Новая банкнота

// Добавить applicability новой банкноте

// Передать банкноту кошельку

// Свопнуть банкноту

// Эксчендж банкнот


// ------------------- Функции, доступные кошелькам & серверу банка ----

// Функция генерирования ключей

// Функция сохранения\загрузки ключей в\из файла

// Функция генерирования UUID

// Функция проверки

// Функция SIGN

// Функции по передаче банкноты

// Функции по проверке подлинности банкноты (без или со свопом)

// Запись в файл структуры данных
void write_odcb_file(
    BANKNOTE_ODCB banknote,
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

// ----------------------- Удобные дополнительные функции для отладки и сериализации --------------------------------


// *.odcb файл переводит в *.json
void odcb2json(
    FILE_PATH path_odcb,
    FILE_PATH path_json,
    int indent
    // ... TODO продумать какие ещё поля
)


// *.json переводит в *.odcb
void json2odcb(
    FILE_PATH path_odcb,
    FILE_PATH path_json
)




#endif /* ODC_SRC_COMMON_H */
