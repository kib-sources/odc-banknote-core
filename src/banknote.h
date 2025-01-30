/**
ODC
odc-banknote-core

Банкноты.
Работа с файлами и с блоками данных в файлах *.odcb

**/
#ifndef ODC_BANKNOTE_H
#define ODC_BANKNOTE_H

#include <stdio.h>
#include "types.h"



// Структура, содержащая указатели на функции по работе с *.odcb файлами
typedef struct{
    // Сами данные
    // blocks -- совокупность указателей на блоки
    // Последний блок -- BLOCK_TAIL
    BLOCKS blocks;
} BANKNOTE_ODCB;




/*
префикс файла, префикс версии
*/


#endif /* ODC_BANKNOTE_H */
