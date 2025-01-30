#ifndef ODC_BANKNOTE_BLOCKS_H
#define ODC_BANKNOTE_BLOCKS_H

#include "types.h"
/**
ODC
odc-banknote-core

Банкноты.
Работа с файлами и с блоками данных в файлах *.odcb

Перечисление типов внутрненних блоков

**/


static const ODCB_FILE_PREFIX prefix = {'O', 'D', 'C', ' ', 'b', 'a', 'n', 'k', 'n', 'o', 't', 'e', '.', '.', '.', '.', '.', '.', '.', '.'}; //"ODC banknote";
static const ODCB_FILE_VERSION version = {'v', '2', '.', '0', '.', '1', '.', '.', '.', '.'}; //"v2.0.1";


/*
Структура файла всегда следующая:
1. ODCB_FILE_PREFIX
2. ODCB_FILE_VERSION
3. BLOCK_HEADER
4. [BLOCK_APPEND_APPLICABILITY] -- произвольное количество, включая 0
5. BLOCK_CHAIN -- первичная передача данных от банка к кошельку
6. [BLOCK_CHAIN] -- произвольное количество
7. BLOCK_TAIL

Так же после любого блока, начиная с блока BLOCK_HEADER может быть сколько угодно блоков BLOCK_COMMENT
Это "джентельменские" (т.е. без защиты) любые блоки с комментариями. Их всегда можно удалить.
А можно оставить.
Они используются для отладки или для удобства взаимодействия программ друг с другом.

При работе с банкнотами рекомендуется оставлять блоки BLOCK_COMMENT.

Важно: блоки BLOCK_COMMENT никак НЕ ЗАЩИЩЕНЫ. Если банкноты вне доверенной среды, использовать
BLOCK_COMMENT не безопасно.

*/

//type(20) + bank_id (36) + banknote_id (36) + 
//code(9) + amount(?) + applicability(16) +
//sign_algorithm(20) + hash_algorithm(20) +
//salt(32) + hash(128) + bank_sign(512)
typedef struct {
    BLOCK_SIZE size;
    BLOCK_TYPE type; // = {'h', 'e', 'a', 'd', 'e', 'r', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'}; //"header.............";

    UUID bin;
    UUID bnid;
    UUID owner;
    CURRENCY_CODE code;
    MONEY_AMOUNT amount;

    APPLICABILITY applicability; // {'A', 'L', 'L', '-', '0', '0', '0', '0', '-', '0', '0', '0', '0', '0', '0'}; "ALL-0000-0000000";
    UINT count_append_applicability_blocks;
    NAME_ALGORITHM sign_algorithm; // {'R', 'S', 'A', '-', '4', '0', '9', '6', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'}; "RSA-4096............";
    NAME_ALGORITHM hash_algorithm; //{'S', 'H', 'A', '-', '5', '1', '2', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'}; "SHA-512.............";

    SALT salt;

    HASH hash;

    PEM_KEY bok;

    SIGN bank_sign;
} BLOCK_HEADER;



// Блок дополнительных требований на банкноту.
typedef struct {
    BLOCK_SIZE size;
    const BLOCK_TYPE type; //= {'a', 'p', 'p', 'e', 'n', 'd', '-', 'a', 'p', 'p', 'l', 'i', 'c', 'a', 'b', 'i', 'l', 'i', 't', 'y'}; //"append-applicability";

    UUID bin;
    UUID bnid;
    // хеш предыдущего
    // BLOCK_HEADER или BLOCK_APPEND_APPLICABILITY
    HASH parent_hash;

    APPLICABILITY applicability;

    SALT salt;

    // hash = hash(bank_id, ..., applicability, salt)
    HASH hash;

    SIGN bank_sign;

} BLOCK_APPEND_APPLICABILITY;


/**

Продумать:
1. Как будеть проходить своп
2. Как будет разрешаться конфликт
3. Нужно ли это в принципе, если можно изъять из обращения старые банкноты и создать ex nihilo новые с новым applicability ?
typedef struct {
    BLOCK_SIZE size;
    const BLOCK_TYPE type = "remove-applicability";

    UUID bank_id;
    UUID banknote_id;
    // хеш предыдущего
    // BLOCK_HEADER или BLOCK_APPEND_APPLICABILITY
    HASH parent_hash;

    APPLICABILITY applicability;

    SALT salt;

    // hash = hash(bank_id, ..., applicability, salt)
    HASH hash;

    SIGN bank_sign;


} BLOCK_REMOVE_APPLICABILITY;
**/



typedef struct {
    BLOCK_SIZE size;
    const BLOCK_TYPE type;// = {'c', 'h', 'a', 'i', 'n', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'}; //"chain...............";

    UUID bin;
    UUID bnid;

    // хеш предыдущего
    // BLOCK_CHAIN или BLOCK_HEADER или BLOCK_APPEND_APPLICABILITY
    HASH parent_hash;

    // [sok_a](bpk) подпись отправителя 
    // KEY sok_owner -- высчитывается из sok_owner_by_bpk через bok
    SIGN sok_owner_by_bpk;

    UINT counter;

    SALT salt0;

    // HASH hash0 = hash(bank_id, banknote_id, parent_hash, sokA_by_bpk, counter, salt)
    HASH hash0;
    SIGN hash0_spk_owner;

    SALT salt;

    // hash = hash(hash0, hash0_spkB, salt)
    HASH hash;

    // Подпись хеша
    SIGN hash_by_spk_or_bpk_previous_owner;


    // ------------------
    // Дополнительные поля -- доп. подтверждение банком.
    // при ОНЛАЙН платеже
    SALT salt_bank;// = {'0'};
    HASH hash_bank;// = {'0'};
    SIGN hash_bank_by_bpk; //= {'0'};    

} BLOCK_CHAIN;

//Замена BLOCK_SWAP
typedef struct {
    BLOCK_SIZE size;
    const BLOCK_TYPE type; //"gap.................";
    
} BLOCK_GAP;


typedef struct {
    BLOCK_SIZE size;
    const BLOCK_TYPE type; //{'c', 'o', 'm', 'm', 'e', 'n', 't', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'}; //"comment.............";

    COMMENT_FIELD comment;

} BLOCK_COMMENT;


typedef struct {
    BLOCK_SIZE size;
    const BLOCK_TYPE type; // = {'t', 'a', 'i', 'l', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.'}; //"tail................";
    COMMENT_FIELD tail_comment;
} BLOCK_TAIL;


static const char _TAIL_COMMENT_PREFIX[70] = "See https://github.com/kib-sources/odc-banknote-core, KIB(c)";

#endif ODC_BANKNOTE_BLOCKS_H