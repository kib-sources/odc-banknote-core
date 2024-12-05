#include <stdio.h>
#include "cryptests.c"

int main()  
{
    UUID bank_id;
    _generate_uuid(bank_id);
    
    UUID banknote_id;
    _generate_uuid(banknote_id);

    CURRENCY_CODE code = {'U', 'S', 'D', ' ', '(', '8', '4', '0', ')'};

    MONEY_AMOUNT amount = 96729;

    APPLICABILITY applicability = {'A', 'L', 'L', '-', '0', '0', '0', '0', '-', '0', '0', '0', '0', '0', '0', '0'};
    
    BLOCK_HEADER banknote;
    BLOCK_HEADER_init(&banknote, bank_id, banknote_id, code, amount, applicability);

    KEYS_PAIR bk = _init_rsa_keys();
    
    BLOCK_HEADER_sign(&banknote, bk.private);

    
    _print_hex(banknote.hash, HASH_SIZE);
    
    
    setup_tests();
    
    
    return 0;  
} 


