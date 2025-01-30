#include <stdio.h>
#include <common.h>
#include <uuid/uuid.h>

void _create_test_banknote()
{
    //constants
    UUID bank_id = {'1', '4', '5', 'a', 'e', '3', 'b', '5', '-', 'a', '4', '0', 'c', '-', '3', 'e', '9', '4', '-', '3', 'd', 'b', 'a', '-', '3', '9', '8', '1', 'f', 'a', '4', '7', '6', 'f', '7', '2'};
    UUID banknote_id = {'2', '1', '5', 'a', 'e', '3', 'b', '5', '-', 'a', '4', '0', 'c', '-', '3', 'e', '9', '4', '-', '3', 'd', 'b', 'a', '-', '3', '9', '8', '1', 'f', 'a', '4', '7', '6', 'f', '7', '2'};
    UUID owner_id = {'3', '1', '5', 'a', 'e', '3', 'b', '5', '-', 'a', '4', '0', 'c', '-', '3', 'e', '9', '4', '-', '3', 'd', 'b', 'a', '-', '3', '9', '8', '1', 'f', 'a', '4', '7', '6', 'f', '7', '2'};
    CURRENCY_CODE code = {'U', 'S', 'D', ' ', '(', '8', '4', '0', ')'};
    MONEY_AMOUNT amount = 96729;
    APPLICABILITY applicability = {'A', 'L', 'L', '-', '0', '0', '0', '0', '-', '0', '0', '0', '0', '0', '0', '0'};

    BLOCK_HEADER banknote;
    BLOCK_HEADER_init(&banknote, bank_id, banknote_id, code, amount, applicability, owner_id);
    printf("Banknote initiated\n");
    char *private_pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                            "MIIJJwIBAAKCAgEA1boiXFai+sDJSPPrIFdNQBss5RYgpvG6G72E7RLrJN/snMsX\n"
                            "jlDw+0aOt8+e5aq7LYpDjwMJ2/put8o/ZFdp/Z4mMsXwPkUQyV0zy+97Z+Ge8L8o\n"
                            "jGr+/br+UE+Jdct8kop3cp1KoEtDHQR3mPKzM24Qb4uZHxIVnQSeUfyPCemA8KDb\n"
                            "kOhnfx9jX7t0/deSx1e9jF4ELMI3DKX/tP89aBvv48aF8/y9LI1iIkEoWari9p5K\n"
                            "dn7LSGqHacmfkZGANYJPp2RPYJgkTgydjpIkuotmu02nBCE6a9Ekd65RxUb3MUew\n"
                            "1lFgM4Grkymdxj5CGjoQch8GghIvbeWfxKgXB6FgIIvI5p5wuVzaDlQe1pGYw0My\n"
                            "kEepgqqpoZK1LeX1UOFPiArrYTh5eiDZgGWPj704AYMZo+hDCSKMZbo4R3F8qtiy\n"
                            "7fOtqbGq8Atm6FydUCnESZettZGPSslzB82EiFzQZ0vnk7HyHagL1L8LFDAgj1k/\n"
                            "k57GfzqApKAeFA7GCL375+vYY72lbaqIg8rchNojS4kBXqdUWTWjTLH/VHyLv2av\n"
                            "W0IwdVAwbapb+ertPDrZDAeaTBZURyp6SCJshjpmRd/s2xUkEhiZEsiSSBAYio26\n"
                            "AL1yssmCrPxD3NsO4lN/LBxbtcZyLcAfFE26nzfQ0d6+gxKd9MKLoxTWtfUCAwEA\n"
                            "AQKCAgAL9GIdI5xwpa1slvYpJDD2O77mXnc7l0xHZnGjuBnugVbxCzwZUgY0q+Tq\n"
                            "O6MB6iuXl8MBIhSgWRDt11J16JzNWpX844z1UrQmaz/tMYtHy3syMKMSPZ7fLuEw\n"
                            "OU6xR81DPhsBznIA5szNd/U/mR20a/zf3GFXd1G9q2c2o0eV8JltfDXj1FgLqIQM\n"
                            "tAXOeAsl+s6npg+aOE/PdY6Iv3keFGf15+IQvGuRbSQW0emxoEkbLc3w9FUnCwxh\n"
                            "eq1h/U88TvppHMeC2ee39OUwNxT2WTtJEUYdCUXFB5kAV8ALppVHjKDD0B/vKZrg\n"
                            "+6QvVUapxGMsmvcoed9syHoIDDXjdW53+c/vPSujfT3JBWnRdLD0W2Nqt/VwFh+o\n"
                            "mOLLCVfTabHl6NBdxXgmeCWHvjwTFah4sH6VyOn7KvPQygh7gUSGtbe4Qg1Syx9G\n"
                            "VB6hMD/EZx9akxJuwTQsY1hvXuVGVNB8zd/ACVKTJat7NyCuUTKoqDQLzBCiAScX\n"
                            "HtL1xwuisTfO+ZOjKIoDhm8mR6sw4/Obxi9kgErYrfv0rB0DGk8qkwMBi40jG23w\n"
                            "Hm1fQ7BLMev/Yw8xB4csxGR1PQuwCBJ4bAlQ/zvZ1UXDKwWgDgXA7uPlK9N9icmd\n"
                            "N9KsEs/5+T72KRPv0FaaXUHK8aC8B6xKKSH30uzwvWrrWVn8QQKCAQEA9DcDBoQH\n"
                            "2tWQvL3ddEPPkB3ZnF1Ig/GjcWy5DTgWKzDKQCqjW5B6nu9enI+ffcGpjeyb6OB9\n"
                            "fXrnKjg2td0V+TM2eE3GU8jW+guRFJcbRRRHGUkU48z64kumzI7A5L8FATRmKWAZ\n"
                            "9TtPeUX3/sKUIyjPPB0ni38o5p34/5L247dDpevYBxZDe4bFoieKZMCtL6VdovnJ\n"
                            "rt95j7GhB4amaox69bUNAJ1NT+M4UG1GcMhqm+AXG96rwyBg3MEPlfDEzhRmwj9w\n"
                            "gjx04U91ehFyMDMFC73r7xs6Ckw3528bmYBI7zOxoRMWZFKqqGKOhwj1FjmsTP8d\n"
                            "RKvi4dLoxOt4wQKCAQEA4Ap7POQBKxN95zN68FAmn4q6I7cNLl0ihfzWC/t3OGTn\n"
                            "LQDQ3yxZcEEvl1qPO043obvXyT0GHkIcxZyjg3Aooro0r9aNVrNNj90k3kR1H/0O\n"
                            "hO6GkpnFV62KN5nVpc50JRkN6DH30gGVgu7vBeG0u479WhG/tpOlL+Vf+9AfNeNn\n"
                            "H3cbyob1dERl5upTcnjBL7iO2WUqhzGbPROMIVqMWidKkw1MCOzmxSFUrpdgLSnW\n"
                            "cSoQhPbbr/uKAtgPyC47jCorntJf3jc0YlEtp47ib0hTGAVmaTVZVh3tXDX0tWS2\n"
                            "dnld83JScKwTu2uRq9RqC8eFAVGMmwjOp0nB/h42NQKCAQA9DnfqLB5OnvBlz85L\n"
                            "IB0Huf7K8iOMIWCsnfMSFACu4a7fJgnbfZ66l7v+xoWoij+a5RoBugaF1bFvw8gh\n"
                            "5dl1iVFH+KHqFp9wum2WSUUfGze/YZ8gaQIci69zGwms5vkYWQJlu8ohnqd6+XxM\n"
                            "LFefBrfxHpThcnRGXB6BvzuMqSf3lqRW+UD75DELHnmiQO3LqLtlYLAE0Yhx3YYV\n"
                            "/JskrmSbg51xluJaY8OTkA55ahIFUJxWcnBdA35UEsyTvzNlFoKuc+/sD7NlFVmY\n"
                            "oD39QPQ1AFG5YQQ8yNt9ODEdSo5xh2oUjFIf2O8j1CgwKJQl71tdkLa/kX3S2ckq\n"
                            "WnjBAoIBADn4vFbPMLYyvvtaSM9yDexueyfOr+x1UP+WotRK51iCU4dDlMiKs0Hm\n"
                            "vCfP2QwheyewcW+zCKg/ty4zD+Rs2zbwM73kKIJstv8o2+dfk2cJlf4zskKw422C\n"
                            "jCdC+ROETm1jBEQ22cdPfZ55sQO2mYuGvmvV9+OIZM/17FY+TjUleIOd0GUhctX4\n"
                            "9N1BeQI/2M0+VkhOcyi0X1T4f+QJiBOz4woWALy2gCg2LbFXnh1RnBmAJvIg5kut\n"
                            "LNL7kWnc/K+SIeNg0Emxwy5FjyiyQklFT6sBirRih5FPASJBG+br/oK9eOALjuV0\n"
                            "wU5X0UPDHQWbRQFIVrevGboTzcyxiJkCggEARGnBFV6JwXgnXNU5CT+eBJ9/hfJm\n"
                            "a6MrDP1fptlyAyz/BTUyoJVm/kXqHytvk1uDpiA+jhbLXDMiWok/TtOBWqNijDKD\n"
                            "43lzv82qikStY5YVLnJCZidZ8wIDDLZZAvjE0HMapdJEvGCQMUOSIDMIkt0vaR0W\n"
                            "oMGsrTTqmnpeEH/lLOo5W8AFpTUJCBYFc+gDYisp3oUwb5EBkN+ax3wBqgdQ16vM\n"
                            "QOGj07Qa1ox7wXz3yecQqciL2qt4KbnjuVLgymmofn5RigkLlF+/sGw813EAgcji\n"
                            "LSEYM+dvytvZm+t+c8eUy53jKiEB2fxjEx9KlkdJiY+nlBVfWZ9or9wCig==\n"
                            "-----END RSA PRIVATE KEY-----\n";

    char *public_pem = "-----BEGIN PUBLIC KEY-----\n"
                           "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1boiXFai+sDJSPPrIFdN\n"
                           "QBss5RYgpvG6G72E7RLrJN/snMsXjlDw+0aOt8+e5aq7LYpDjwMJ2/put8o/ZFdp\n"
                           "/Z4mMsXwPkUQyV0zy+97Z+Ge8L8ojGr+/br+UE+Jdct8kop3cp1KoEtDHQR3mPKz\n"
                           "M24Qb4uZHxIVnQSeUfyPCemA8KDbkOhnfx9jX7t0/deSx1e9jF4ELMI3DKX/tP89\n"
                           "aBvv48aF8/y9LI1iIkEoWari9p5Kdn7LSGqHacmfkZGANYJPp2RPYJgkTgydjpIk\n"
                           "uotmu02nBCE6a9Ekd65RxUb3MUew1lFgM4Grkymdxj5CGjoQch8GghIvbeWfxKgX\n"
                           "B6FgIIvI5p5wuVzaDlQe1pGYw0MykEepgqqpoZK1LeX1UOFPiArrYTh5eiDZgGWP\n"
                           "j704AYMZo+hDCSKMZbo4R3F8qtiy7fOtqbGq8Atm6FydUCnESZettZGPSslzB82E\n"
                           "iFzQZ0vnk7HyHagL1L8LFDAgj1k/k57GfzqApKAeFA7GCL375+vYY72lbaqIg8rc\n"
                           "hNojS4kBXqdUWTWjTLH/VHyLv2avW0IwdVAwbapb+ertPDrZDAeaTBZURyp6SCJs\n"
                           "hjpmRd/s2xUkEhiZEsiSSBAYio26AL1yssmCrPxD3NsO4lN/LBxbtcZyLcAfFE26\n"
                           "nzfQ0d6+gxKd9MKLoxTWtfUCAwEAAQ==\n"
                           "-----END PUBLIC KEY-----\n";


    //printf("Key size pub: %d\n", strlen(public_pem));
    //printf("Key size priv: %d\n", strlen(private_pem));
    PEM_KEY public;
    public.len = 800;
    public.pem_key = public_pem;

    PEM_KEY private;
    private.len = 3243;
    private.pem_key = private_pem;

    

    KEYS_PAIR rsa_pem_keys;// = _init_rsa_keys();
    rsa_pem_keys.private = private;
    rsa_pem_keys.public = public;
    //printf("%s\n %s\n", rsa_pem_keys.private.pem_key, rsa_pem_keys.public.pem_key);

    BLOCK_HEADER_sign(&banknote, rsa_pem_keys);
    _print_banknote_header(&banknote);

    char *test_concat = BLOCK_HEADER_concatenate_all_fields(&banknote);
    printf("Test concat: %s\n", test_concat);

    printf("Resulkt: %d\n", BLOCK_HEADER_verify(&banknote));

    size_t decoded_len = 0;
    BYTE *bytes = _base64_2_bytes(public_pem, &decoded_len);
    _print_hex(bytes, decoded_len);
    free(bytes);
}


int main() {
    _create_test_banknote();

    
    
    return 0;  
} 
