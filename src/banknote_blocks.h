/**
ODC
odc-banknote-core

Банкноты.
Работа с файлами и с блоками данных в файлах *.odcb

Перечисление типов внутрненних блоков

**/


const ODCB_FILE_PREFIX prefix = "ODC banknote........";
const ODCB_FILE_VERSION version = "v2.0.1....";


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



typedef struct {
    BLOCK_SIZE size;
    const BLOCK_TYPE type = "header..............";

    UUID bank_id;
    UUID banknote_id;
    CURRENCY_CODE code;
    MONEY_AMOUNT amount;

    APPLICABILITY applicability = "ALL-0000-0000000";

    NAME_ALGORITHM sign_algorithm = "RSA-4096............";
    NAME_ALGORITHM hash_algorithm = "SHA-512.............";

    SALT salt;

    // hash = hash(bank_id, ..., sign_algorithm, hash_algorithm, salt)
    HASH hash;

    SIGN bank_sign;


} BLOCK_HEADER;



// Блок дополнительных требований на банкноту.
typedef struct {
    BLOCK_SIZE size;
    const BLOCK_TYPE type = "append-applicability";

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



typedef struct{
    BLOCK_SIZE size;
    const BLOCK_TYPE type = "chain...............";

    UUID bank_id;
    UUID banknote_id;

    // хеш предыдущего
    // BLOCK_CHAIN или BLOCK_HEADER или BLOCK_APPEND_APPLICABILITY
    HASH parent_hash;

    // [sok_a](bpk) подпись отправителя 
    SIGN sokA_by_bpk;

    UINT counter;

    SALT salt0;

    // HASH hash0 = hash(bank_id, banknote_id, parent_hash, sokA_by_bpk, counter, salt)
    HASH hash0;
    SIGN hash0_spkB;

    SALT salt;

    // hash = hash(hash0, hash0_spkB, salt)
    HASH hash;

    // Подпись хеша
    SIGN hash_by_spkA;


    // ------------------
    // Дополнительные поля -- доп. подтверждение банком.
    // при ОНЛАЙН платеже
    SALT salt_bank = 0;
    HASH hash_bank = 0;
    SIGN hash_bank_by_bpk = 0;
    

} BLOCK_CHAIN;


typedef struct{
    BLOCK_SIZE size;
    const BLOCK_TYPE type = "comment.............";

    COMMENT_FIELD comment;

} BLOCK_COMMENT;


typedef struct{
    BLOCK_SIZE size;
    const BLOCK_TYPE type = "swap................";

    UUID banknote_id;
    UUID bank_id;

    // хеш последнего "слева" блока перед схлопыванием сервером
    // BLOCK_CHAIN или BLOCK_HEADER
    HASH parent_left;

    // хеш первого "справа" блока перед схлопыванием сервером
    // BLOCK_CHAIN или BLOCK_HEADER
    HASH parent_right;

    SALT salt;
    // HASH hash = hash(bank_id, banknote_id, parent_left, parent_right, salt)
    HASH hash;
    SIGN hash_by_bpk;

} BLOCK_SWAP;



typedef struct{
    BLOCK_SIZE size;
    const BLOCK_TYPE type = "tail................";
    COMMENT_FIELD tail_comment;
} BLOCK_TAIL;

const char[] _TAIL_COMMENT_PREFIX = "See https://github.com/kib-sources/odc-banknote-core, KIB(c)"
