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




#endif /* ODC_SRC_COMMON_H */
