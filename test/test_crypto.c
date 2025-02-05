#include "unity.c"
#include "common.h"
#include <string.h>


void setUp(void) {};
void tearDown(void) {};


void test_sha512_1()
{
    HASH hash;
    _get_hash_sha512("string", hash);
    
    unsigned char *produced_hash = _bytes_2_hex(hash, HASH_SIZE);

    unsigned char *correct_hash = ("2757cb3cafc39af451abb2697be79b4ab61d63d74d85b0418629de8c26811b529f3f3780d0150063ff55a2beee74c4ec102a2a2731a1f1f7f10d473ad18a6a87");
    
    TEST_ASSERT_EQUAL_STRING(correct_hash, produced_hash);
}

void test_sha512_2()
{
    HASH hash;
    _get_hash_sha512("important", hash);
    
    unsigned char *produced_hash = _bytes_2_hex(hash, HASH_SIZE);

    unsigned char *correct_hash = ("09cdb9fc303c7ceaa74c5427dee2b09bec82338b2fc6cab21e54130a353b2b0a86bde09bbe27b0597789a7868a548406c5dfd057964a7e88441adbe0af1b357e");
    
    TEST_ASSERT_EQUAL_STRING(correct_hash, produced_hash);
}


void test_rsa4096_sign_1()
{
    char *private_key_pem = "-----BEGIN RSA PRIVATE KEY-----\n"
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

    RSA *private_key = pem_to_rsa_private_key(private_key_pem);
    
    SIGN signature;

    char *plain_text = "Message";
    
    _get_signature_rsa4096(plain_text, private_key, signature);

    unsigned char *produced_signature = _bytes_2_hex(signature, SIGN_SIZE);
    
    unsigned char *correct_signature = "90b7976f95f097e03fa978cf33093df0147dd933923c914a277999fe27ab73de72a655ad4f5f83fc60b03bece60b0081f0fc7c59c64e02166e0aa3d0eed4a2bf247e6352f1fe0ec3be8bdab0e1b5a9b7dc1ef6d2c1a78dfe332d00b23e1bc45c28ae065f4c0cebaa1877dfd271a58c9f46900c34718576a6021415b37b23c5ab3c649f0af3a8dd9b1726604fdc0562a6d6c3eddb8c6473f8afdfa30295505ef6fac67b48ef79d640ccc3440d328f8e3d48d58aa557b35b6bdc3fe1fcad6ad2fb66c0a33714ba5ad2a45eceee1149fd2088c02e29c297449d40ea2f513eb2c20a74a07df025ea196ce4f155f9ac4b2aff883dd52e3ee80a493c774af9c796a34e262f176ea65428f8043554bc6039f33ef9833a1ab2a967ed6f7091d4fd60a2e1f85aa395ee6ed19115eb56c469028ff79c4654ac58a56aa234df7121dd09ad05969eebe7c87fca097b60c3879531ed44b36f9fbdba425c0b7bd82da484b76964b63e2ef6080577a3267cd6904d6b390b321075f490dcb4b0f47a5815af0ce10f26790ee5991b210c5a1fb4d29a6da74d3593993e36213bd3ff182963220f278649711c7a147eb0e79a809ce18aef6ea4a193d68a8cd658e5f8ba91cd08670692b6a5d9559d898b484ceb57cc7feed55917f55fb523878ad7ab97e9fcc21792de8721860f3a045d14c08297039922c926dcc79afd94c001fab6d7a08877dbf03e";

    TEST_ASSERT_EQUAL_STRING(correct_signature, produced_signature);
}


void test_rsa4096_sign_2()
{
    char *private_key_pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                            "MIIJKAIBAAKCAgEAlzqIm5/MGPl6WZG/0U2J8DfP+pcukjM9PEmKicKQLs0pQgsv\n"
                            "7i2fZWd1bD08PhvrVsRF5Li+NrKBwUuf4s/RKZZqBvAjBTBmtTDsiIQy/jWbfiWJ\n"
                            "Ygq0rtw9Doz92clBe4v8Ar7Kf8r3FR+gHFlRJSB7AvtXr5HgaKoTRKNiQbS+mYPz\n"
                            "67rOT7heU5sN/4aO50gVRWYZpSe2lKN0qH/iQpZ4RFuivd/pO5NcdOQRViC2oE3b\n"
                            "nw3HjuTcRN6OVzOMLWB0GinADeiGfsA17+uBJI0wkLTTiWZ6oK57f0cdm9AWZbzF\n"
                            "jQikm9fxgbi1r4zVIWLhS32+iYUnbqTCBwcl0+/7ezR9uWhCcAAl+qo7A9TsmbnJ\n"
                            "uTbwF8dM/VCmvx8wQzEwZYg5xFEoPj1UUmGDuh4JIvf9mC43xtbCn0O5032B64ov\n"
                            "j8Odj3Hk3Srl/amMzzEAEk850F4V/Pr8hoG3Z5y6XlMT3qjHNb6JUZj6+uALDRrl\n"
                            "eUIOpbP3fyL2LKqGJ6f6M5eABt57g08Jnf3nPNEszNCdvz+TW3OIqIxp87vh0wOK\n"
                            "xWskxatr3I3/r+021plvDcwrSxwnmzwqUIoOPlzIyci3tg4moDcGOnWXp/Wxxhj4\n"
                            "P9IU6JiszBhqr18iUHL70EBA2OuKnbCqsWyXU3qAD3nFAPwtgpNsprsaZeUCAwEA\n"
                            "AQKCAgAApy0N1vvPo8wmdN2qLraIxgTs5Rg7Y2NBTmP9wkxTF2m1Mk0rryDAFFlK\n"
                            "dV08O2yhvEk8+ps/qzeqOQRgu1sA3fhpPUI5dIMNB0AOOtvpgxu/yLO2K6uqEaNl\n"
                            "27AA78CLowgcjuxa7upwOem8FZqnGWPOmH1BcdTRPuLEahwzgm9MRGiaPP1FFNu7\n"
                            "arD9yHv3fbUxzoYP04MTUz1euOamOPYd/XNPdJcSPcmpa46zm4KOYKexISMad9yH\n"
                            "o5pjwAI78+2saz+8D6P9CiFxfsfY+48ZIN7E+h9PcFFyNEFpedWO7OjBeicT0TPm\n"
                            "xoBqWKZW9ZFZfRqEh4GrFaUM2LgOF4js4b06tN/PoTjyjXhMNbe1qT3nmr8I77mV\n"
                            "cLkssYphGN7OuM8Op7J9S6DKhyci2aycwZPJ9RT9wtwredL5Tdtg7zbIbazUXMot\n"
                            "gV5dbGRLSN2tj6hBjSzXMeknnJWzxA3aE23Ki5mARvcZKQAg0f/Ktqad5UhmcPft\n"
                            "aLcOfpSrVlElLHaITR+lxvp3md850X4YoELeefFe/X2zvoYLawhR0JxSeV0LsuNt\n"
                            "yejELaxWp4I4FmnW16iI0sf5LenbKa0lU6zI2Sk5Lj9s4OAycmrn2UHVK6Z4bwVB\n"
                            "ptTTxeXBm6QvtaXuy+X6pQh2YVSNwwhQSIDe9JG3VtryCT7CoQKCAQEAy5Cii7CS\n"
                            "WUXiTNR52dRMvByHrFIKueeOTyBsF9zpHyGhniGu44pQlhMaVvt5tdIYt0lFsxUA\n"
                            "wiTtU2b2um1s+ihhb6PfUJaCFq7zzGlNPIzKh7iq7zx4YdEVg1YZgx/oHUfsGcA/\n"
                            "Eqmr6JIkGRnkHBosEunweNCex5F2ZafhLGjHxDljj3V4fW55EhF3kRfk+DgIE8pM\n"
                            "cueCKvY5sl+Ydys/xyPJsYSlKhGW1uqZYzkXbh+jG+z28lhfq+zcLdjt31mMto2r\n"
                            "Xl4fBi7rxIS68EyvWfkHFgiDlAzWP2n88AXRH3CjSotHVhc4Jj++DdGWSbf+PXaA\n"
                            "LPjMoMIvtACGiQKCAQEAvi7EKD+h/VS/bDzmp9R188wcDA0UHmCR0/jbHudPeTTz\n"
                            "qqnEjyzFXcdaEbBzaCc5i2tZBuc0CJ1k9H6iNatESqW2zBoIr2bntS5obCxeU+1Q\n"
                            "gJslCVBgpCs9oPHwZW55YtiMNATydJp72FbzhCQw4iSzZqqH+OsN06QcDzPfRPor\n"
                            "b4dhHuwDYgB3ILSvndCHJB1eMfmtxKsBNdqWcxuYtgZRQ4Paih3PJscdm3FG/U/E\n"
                            "vCjibV6ppk1wpiJaOrTLCHZ477BaVxF3t/tggt8SdT7a5UczxlLggNWgvIbvSnLh\n"
                            "kT33vQsaVIXm4viZGS2vF2J3nsSXBq7p5b522vXNfQKCAQBm+g7QPY17LbgSB7Zw\n"
                            "dE4xJvmXOZWFf9bkvlEQLUec4QWCGiX/o1uq35UGhYaHbPXl2mIw+qH8lHOeKksL\n"
                            "+gkT71ODB1IT0V+TnANm16ojxFE8ITYPefan/P42B1s2kvB3x4dva2o8xapaJ3ut\n"
                            "WwSjFrZPBxsH8vkvma1cNXXaYlMUN7fevZ0rTrReaImk04KX8rhbUo4j3mth0ldT\n"
                            "nbpiJnXIBpmkfKaUxnsY02qu4BWzNrvrh49Q/1W+gj7Lzp5ey008mCQlw9VL6naI\n"
                            "XmC26QQXrrtf8QSm42uKftJelYK5teBU+Goo6ewUpVA+a1Tsi/BIJWcn2OCjPjil\n"
                            "hVKJAoIBAAvea0t/vSJMOa4Nlu9+aOYQJOfzoP/MUw2BiFtDYEhWL6bE9Ylh5+dU\n"
                            "W6Ci/HDRkdvLlUDDCRJIkFZZ2NG0oIxwDxppvYUEzQ0Xmli15CUkuFNuWz9bjsxw\n"
                            "DmaO8svBuz2Z+hX9AQyZ34S+2G+0uoBCfhe4KMg2EyTUJxQjzplFa5SIRF1jqUpi\n"
                            "cQzPee5FZ0mvs4M268tMSMUNoToJzNv/RO8LuYXJGnZ3Erfyt9VzNvnvK0JcGAZS\n"
                            "6ubTWgIz6j/a9O0welLYujn3LCy+sy4yAAMzEF4eKfigXGmnmiNxS/Z+gYmAueHw\n"
                            "gVpE3XkeysCQ2ppD9pDqNZqq6kv77xkCggEBAKYLQXIxtLCxy2Hi7wV+9j+aKyrL\n"
                            "gImTqHWTsFjkIukR92IeBFm6VQb55zI28Uwx964enaeekceaobqejatKrJKrlzJW\n"
                            "8fJ3of5sXPkWu6blW+xIWWqanswn5eG2pLaXfmR9tIiBBL3STpLYcNpcggW3K1f/\n"
                            "MU8l1g1z5qbOSFQVIAa8MTJ48zR6B3Kbdu7oYmV0P18IWSTxgATHnIXfLeSwrC5/\n"
                            "A78vHSfGPirZAPIAFz56vVNCxyX7GuUoSRKV0P4sjmny7BnWX/K+1ntR8H728wi3\n"
                            "g07vzLFefg7gINFqelEptjg/pXDqHv6K2YW28fpavuv4yMHticseFGGWbLE=\n"
                            "-----END RSA PRIVATE KEY-----\n";
    
    SIGN signature;

    RSA *private_key = pem_to_rsa_private_key(private_key_pem);

    char *plain_text = "Very very important";
    
    _get_signature_rsa4096(plain_text, private_key, signature);

    unsigned char *produced_signature = _bytes_2_hex(signature, SIGN_SIZE);
    
    unsigned char *correct_signature = "2cfeb2e5d25c90f8476ed9b3a9a6b4348efb8fc1e21e83fd5468fc70b43539967e72ccc7433b7ddfe3f51437b6656af9500b06ddc25a2468d6120bd03724dc8229ef8e091cd29e910e436e5f8affd3b47bc9ac46af622b52244ee26253ce85e8bee6e7c9e89046ef4e4b47f9bd6814076d6c76ce96f708411570fa54cca4fadb963138d65ca6421b4fc07847639ed1f1e1a04f889b32fe81bc55d2d00b04d44a598bb50b6b0cfc84d7caf9e0793114bfcb273941180c4d040958e17fb6d139a50193120f37e825de9b5a259f27fc2fc19e2b0f2bfa29d4f412a482b0f9290b020dac233bc9c8555f13b95fc97c8f19293f143673a8e937e69cef6c22c4076ae4176ad41566c37a776c706f1d198ca0e7564082260e0674c993f34b540e041af5aec95a9c1f5ff659e4eefeb8562e22c9483062d4e93f71a64a16ccdb3e3e633bad69633572d9b065c10f0b966246bf871ce0cc73dc6389edccbf35ea77b89bc239d3f82f4417ddce42efc3ae57057175e59f064e0e3b425cb55285a1044fa6f0c9720bc7e59f5a357b31ab210b1da8cb8320d6ded522943261ad90d67bd8c9621060d689c80543f20545f1ae1b933f19b6fdd105cb185a0815a2e3e4a57093da82069fc11ecfebed916799ada89eb0c0a66a3c033979a5fcea5235c89e4f17f9296d8275f21e30d9fcbd3b53c628617afcd9cc0f4ab6ea84ee150b564f1a2023";

    TEST_ASSERT_EQUAL_STRING(correct_signature, produced_signature);
}


void test_rsa4096_verify_1()
{
    unsigned char *signature = "90b7976f95f097e03fa978cf33093df0147dd933923c914a277999fe27ab73de72a655ad4f5f83fc60b03bece60b0081f0fc7c59c64e02166e0aa3d0eed4a2bf247e6352f1fe0ec3be8bdab0e1b5a9b7dc1ef6d2c1a78dfe332d00b23e1bc45c28ae065f4c0cebaa1877dfd271a58c9f46900c34718576a6021415b37b23c5ab3c649f0af3a8dd9b1726604fdc0562a6d6c3eddb8c6473f8afdfa30295505ef6fac67b48ef79d640ccc3440d328f8e3d48d58aa557b35b6bdc3fe1fcad6ad2fb66c0a33714ba5ad2a45eceee1149fd2088c02e29c297449d40ea2f513eb2c20a74a07df025ea196ce4f155f9ac4b2aff883dd52e3ee80a493c774af9c796a34e262f176ea65428f8043554bc6039f33ef9833a1ab2a967ed6f7091d4fd60a2e1f85aa395ee6ed19115eb56c469028ff79c4654ac58a56aa234df7121dd09ad05969eebe7c87fca097b60c3879531ed44b36f9fbdba425c0b7bd82da484b76964b63e2ef6080577a3267cd6904d6b390b321075f490dcb4b0f47a5815af0ce10f26790ee5991b210c5a1fb4d29a6da74d3593993e36213bd3ff182963220f278649711c7a147eb0e79a809ce18aef6ea4a193d68a8cd658e5f8ba91cd08670692b6a5d9559d898b484ceb57cc7feed55917f55fb523878ad7ab97e9fcc21792de8721860f3a045d14c08297039922c926dcc79afd94c001fab6d7a08877dbf03e";

    SIGN sign;
    _hex_2_bytes(signature, sign, SIGN_SIZE);
    
    char *public_key_pem = "-----BEGIN PUBLIC KEY-----\n"
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

    RSA *public_rsa = pem_to_rsa_public_key(public_key_pem);

    char *plain_text = "Message";

    int verify_status = _verify_signature_rsa4096(plain_text, public_rsa, sign);
   
    RSA_free(public_rsa);

    TEST_ASSERT_EQUAL_INT(1, verify_status);
}


void test_rsa4096_verify_2()
{
    unsigned char *signature = "2cfeb2e5d25c90f8476ed9b3a9a6b4348efb8fc1e21e83fd5468fc70b43539967e72ccc7433b7ddfe3f51437b6656af9500b06ddc25a2468d6120bd03724dc8229ef8e091cd29e910e436e5f8affd3b47bc9ac46af622b52244ee26253ce85e8bee6e7c9e89046ef4e4b47f9bd6814076d6c76ce96f708411570fa54cca4fadb963138d65ca6421b4fc07847639ed1f1e1a04f889b32fe81bc55d2d00b04d44a598bb50b6b0cfc84d7caf9e0793114bfcb273941180c4d040958e17fb6d139a50193120f37e825de9b5a259f27fc2fc19e2b0f2bfa29d4f412a482b0f9290b020dac233bc9c8555f13b95fc97c8f19293f143673a8e937e69cef6c22c4076ae4176ad41566c37a776c706f1d198ca0e7564082260e0674c993f34b540e041af5aec95a9c1f5ff659e4eefeb8562e22c9483062d4e93f71a64a16ccdb3e3e633bad69633572d9b065c10f0b966246bf871ce0cc73dc6389edccbf35ea77b89bc239d3f82f4417ddce42efc3ae57057175e59f064e0e3b425cb55285a1044fa6f0c9720bc7e59f5a357b31ab210b1da8cb8320d6ded522943261ad90d67bd8c9621060d689c80543f20545f1ae1b933f19b6fdd105cb185a0815a2e3e4a57093da82069fc11ecfebed916799ada89eb0c0a66a3c033979a5fcea5235c89e4f17f9296d8275f21e30d9fcbd3b53c628617afcd9cc0f4ab6ea84ee150b564f1a2023";

    SIGN sign;
    _hex_2_bytes(signature, sign, SIGN_SIZE);

    char *public_key_pem = "-----BEGIN PUBLIC KEY-----\n"
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlzqIm5/MGPl6WZG/0U2J\n"
        "8DfP+pcukjM9PEmKicKQLs0pQgsv7i2fZWd1bD08PhvrVsRF5Li+NrKBwUuf4s/R\n"
        "KZZqBvAjBTBmtTDsiIQy/jWbfiWJYgq0rtw9Doz92clBe4v8Ar7Kf8r3FR+gHFlR\n"
        "JSB7AvtXr5HgaKoTRKNiQbS+mYPz67rOT7heU5sN/4aO50gVRWYZpSe2lKN0qH/i\n"
        "QpZ4RFuivd/pO5NcdOQRViC2oE3bnw3HjuTcRN6OVzOMLWB0GinADeiGfsA17+uB\n"
        "JI0wkLTTiWZ6oK57f0cdm9AWZbzFjQikm9fxgbi1r4zVIWLhS32+iYUnbqTCBwcl\n"
        "0+/7ezR9uWhCcAAl+qo7A9TsmbnJuTbwF8dM/VCmvx8wQzEwZYg5xFEoPj1UUmGD\n"
        "uh4JIvf9mC43xtbCn0O5032B64ovj8Odj3Hk3Srl/amMzzEAEk850F4V/Pr8hoG3\n"
        "Z5y6XlMT3qjHNb6JUZj6+uALDRrleUIOpbP3fyL2LKqGJ6f6M5eABt57g08Jnf3n\n"
        "PNEszNCdvz+TW3OIqIxp87vh0wOKxWskxatr3I3/r+021plvDcwrSxwnmzwqUIoO\n"
        "PlzIyci3tg4moDcGOnWXp/Wxxhj4P9IU6JiszBhqr18iUHL70EBA2OuKnbCqsWyX\n"
        "U3qAD3nFAPwtgpNsprsaZeUCAwEAAQ==\n"
        "-----END PUBLIC KEY-----\n";

    RSA *public_rsa = pem_to_rsa_public_key(public_key_pem);

    char *plain_text = "Very very important";

    int verify_status = _verify_signature_rsa4096(plain_text, public_rsa, sign);
   
    RSA_free(public_rsa);

    TEST_ASSERT_EQUAL_INT(1, verify_status);
}


void test_init_rsa_keys()
{
    KEYS_PAIR rsa_pem_keys = _init_rsa_keys();

    char *plain_text = "header..........uuid90943486774937757";

    //Подпись
    SIGN signature;

    RSA *private_key = pem_to_rsa_private_key(rsa_pem_keys.private.pem_key);
    
    _get_signature_rsa4096(plain_text, private_key, signature);

    //Проверка
    RSA *public_rsa = pem_to_rsa_public_key(rsa_pem_keys.public.pem_key);

    int verify_status = _verify_signature_rsa4096(plain_text, public_rsa, signature);
   
    RSA_free(public_rsa);

    TEST_ASSERT_EQUAL_INT(1, verify_status);
}


void test_base64_2_bytes_convertion()
{
    char *base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    size_t bytes_size;
    BYTE *produced_bytes = _base64_2_bytes(base64, &bytes_size);

    char *produced_bytes_hex = _bytes_2_hex(produced_bytes, bytes_size);

    char *expected_bytes_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    TEST_ASSERT_EQUAL_STRING(expected_bytes_hex, produced_bytes_hex);
}


void test_bytes_2_base64_convertion()
{
    char *bytes_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    BYTE *bytes;
    _hex_2_bytes(bytes_hex, bytes, strlen(bytes_hex) / 2);

    size_t produced_base64_size;
    char *produced_base64 = _bytes_2_base64(bytes, strlen(bytes_hex) / 2, &produced_base64_size);
    
    char *expected_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    TEST_ASSERT_EQUAL_STRING(expected_base64, produced_base64);
}


void test_pem_2_bytes_convertion_public()
{
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

    size_t key_size;
    BYTE *key_bytes = _pem_2_bytes(public_pem, &key_size);


    char *produced_bytes_hex = _bytes_2_hex(key_bytes, key_size);

    char *expected_bytes_hex = "30820222300d06092a864886f70d01010105000382020f003082020a0282020100d5ba225c56a2fac0c948f3eb20574d401b2ce51620a6f1ba1bbd84ed12eb24dfec9ccb178e50f0fb468eb7cf9ee5aabb2d8a438f0309dbfa6eb7ca3f645769fd9e2632c5f03e4510c95d33cbef7b67e19ef0bf288c6afefdbafe504f8975cb7c928a77729d4aa04b431d047798f2b3336e106f8b991f12159d049e51fc8f09e980f0a0db90e8677f1f635fbb74fdd792c757bd8c5e042cc2370ca5ffb4ff3d681befe3c685f3fcbd2c8d6222412859aae2f69e4a767ecb486a8769c99f91918035824fa7644f6098244e0c9d8e9224ba8b66bb4da704213a6bd12477ae51c546f73147b0d651603381ab93299dc63e421a3a10721f0682122f6de59fc4a81707a160208bc8e69e70b95cda0e541ed69198c343329047a982aaa9a192b52de5f550e14f880aeb6138797a20d980658f8fbd38018319a3e84309228c65ba3847717caad8b2edf3ada9b1aaf00b66e85c9d5029c44997adb5918f4ac97307cd84885cd0674be793b1f21da80bd4bf0b1430208f593f939ec67f3a80a4a01e140ec608bdfbe7ebd863bda56daa8883cadc84da234b89015ea7545935a34cb1ff547c8bbf66af5b42307550306daa5bf9eaed3c3ad90c079a4c1654472a7a48226c863a6645dfecdb152412189912c8924810188a8dba00bd72b2c982acfc43dcdb0ee2537f2c1c5bb5c6722dc01f144dba9f37d0d1debe83129df4c28ba314d6b5f50203010001";
  
    TEST_ASSERT_EQUAL_STRING(expected_bytes_hex, produced_bytes_hex);
}


void test_bytes_2_pem_convertion_public()
{
    char *bytes_hex = "30820222300d06092a864886f70d01010105000382020f003082020a0282020100d5ba225c56a2fac0c948f3eb20574d401b2ce51620a6f1ba1bbd84ed12eb24dfec9ccb178e50f0fb468eb7cf9ee5aabb2d8a438f0309dbfa6eb7ca3f645769fd9e2632c5f03e4510c95d33cbef7b67e19ef0bf288c6afefdbafe504f8975cb7c928a77729d4aa04b431d047798f2b3336e106f8b991f12159d049e51fc8f09e980f0a0db90e8677f1f635fbb74fdd792c757bd8c5e042cc2370ca5ffb4ff3d681befe3c685f3fcbd2c8d6222412859aae2f69e4a767ecb486a8769c99f91918035824fa7644f6098244e0c9d8e9224ba8b66bb4da704213a6bd12477ae51c546f73147b0d651603381ab93299dc63e421a3a10721f0682122f6de59fc4a81707a160208bc8e69e70b95cda0e541ed69198c343329047a982aaa9a192b52de5f550e14f880aeb6138797a20d980658f8fbd38018319a3e84309228c65ba3847717caad8b2edf3ada9b1aaf00b66e85c9d5029c44997adb5918f4ac97307cd84885cd0674be793b1f21da80bd4bf0b1430208f593f939ec67f3a80a4a01e140ec608bdfbe7ebd863bda56daa8883cadc84da234b89015ea7545935a34cb1ff547c8bbf66af5b42307550306daa5bf9eaed3c3ad90c079a4c1654472a7a48226c863a6645dfecdb152412189912c8924810188a8dba00bd72b2c982acfc43dcdb0ee2537f2c1c5bb5c6722dc01f144dba9f37d0d1debe83129df4c28ba314d6b5f50203010001";

    BYTE *bytes;
    _hex_2_bytes(bytes_hex, bytes, strlen(bytes_hex) / 2);

    size_t pem_size;
    char *produced_pem = _bytes_2_pem(bytes, strlen(bytes_hex) / 2, &pem_size, 1);


    char *expected_pem = "-----BEGIN PUBLIC KEY-----\n"
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

    TEST_ASSERT_EQUAL_STRING(expected_pem, produced_pem);
}


void test_pem_2_bytes_convertion_private()
{
    char *private_pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                            "MIIJKAIBAAKCAgEAlzqIm5/MGPl6WZG/0U2J8DfP+pcukjM9PEmKicKQLs0pQgsv\n"
                            "7i2fZWd1bD08PhvrVsRF5Li+NrKBwUuf4s/RKZZqBvAjBTBmtTDsiIQy/jWbfiWJ\n"
                            "Ygq0rtw9Doz92clBe4v8Ar7Kf8r3FR+gHFlRJSB7AvtXr5HgaKoTRKNiQbS+mYPz\n"
                            "67rOT7heU5sN/4aO50gVRWYZpSe2lKN0qH/iQpZ4RFuivd/pO5NcdOQRViC2oE3b\n"
                            "nw3HjuTcRN6OVzOMLWB0GinADeiGfsA17+uBJI0wkLTTiWZ6oK57f0cdm9AWZbzF\n"
                            "jQikm9fxgbi1r4zVIWLhS32+iYUnbqTCBwcl0+/7ezR9uWhCcAAl+qo7A9TsmbnJ\n"
                            "uTbwF8dM/VCmvx8wQzEwZYg5xFEoPj1UUmGDuh4JIvf9mC43xtbCn0O5032B64ov\n"
                            "j8Odj3Hk3Srl/amMzzEAEk850F4V/Pr8hoG3Z5y6XlMT3qjHNb6JUZj6+uALDRrl\n"
                            "eUIOpbP3fyL2LKqGJ6f6M5eABt57g08Jnf3nPNEszNCdvz+TW3OIqIxp87vh0wOK\n"
                            "xWskxatr3I3/r+021plvDcwrSxwnmzwqUIoOPlzIyci3tg4moDcGOnWXp/Wxxhj4\n"
                            "P9IU6JiszBhqr18iUHL70EBA2OuKnbCqsWyXU3qAD3nFAPwtgpNsprsaZeUCAwEA\n"
                            "AQKCAgAApy0N1vvPo8wmdN2qLraIxgTs5Rg7Y2NBTmP9wkxTF2m1Mk0rryDAFFlK\n"
                            "dV08O2yhvEk8+ps/qzeqOQRgu1sA3fhpPUI5dIMNB0AOOtvpgxu/yLO2K6uqEaNl\n"
                            "27AA78CLowgcjuxa7upwOem8FZqnGWPOmH1BcdTRPuLEahwzgm9MRGiaPP1FFNu7\n"
                            "arD9yHv3fbUxzoYP04MTUz1euOamOPYd/XNPdJcSPcmpa46zm4KOYKexISMad9yH\n"
                            "o5pjwAI78+2saz+8D6P9CiFxfsfY+48ZIN7E+h9PcFFyNEFpedWO7OjBeicT0TPm\n"
                            "xoBqWKZW9ZFZfRqEh4GrFaUM2LgOF4js4b06tN/PoTjyjXhMNbe1qT3nmr8I77mV\n"
                            "cLkssYphGN7OuM8Op7J9S6DKhyci2aycwZPJ9RT9wtwredL5Tdtg7zbIbazUXMot\n"
                            "gV5dbGRLSN2tj6hBjSzXMeknnJWzxA3aE23Ki5mARvcZKQAg0f/Ktqad5UhmcPft\n"
                            "aLcOfpSrVlElLHaITR+lxvp3md850X4YoELeefFe/X2zvoYLawhR0JxSeV0LsuNt\n"
                            "yejELaxWp4I4FmnW16iI0sf5LenbKa0lU6zI2Sk5Lj9s4OAycmrn2UHVK6Z4bwVB\n"
                            "ptTTxeXBm6QvtaXuy+X6pQh2YVSNwwhQSIDe9JG3VtryCT7CoQKCAQEAy5Cii7CS\n"
                            "WUXiTNR52dRMvByHrFIKueeOTyBsF9zpHyGhniGu44pQlhMaVvt5tdIYt0lFsxUA\n"
                            "wiTtU2b2um1s+ihhb6PfUJaCFq7zzGlNPIzKh7iq7zx4YdEVg1YZgx/oHUfsGcA/\n"
                            "Eqmr6JIkGRnkHBosEunweNCex5F2ZafhLGjHxDljj3V4fW55EhF3kRfk+DgIE8pM\n"
                            "cueCKvY5sl+Ydys/xyPJsYSlKhGW1uqZYzkXbh+jG+z28lhfq+zcLdjt31mMto2r\n"
                            "Xl4fBi7rxIS68EyvWfkHFgiDlAzWP2n88AXRH3CjSotHVhc4Jj++DdGWSbf+PXaA\n"
                            "LPjMoMIvtACGiQKCAQEAvi7EKD+h/VS/bDzmp9R188wcDA0UHmCR0/jbHudPeTTz\n"
                            "qqnEjyzFXcdaEbBzaCc5i2tZBuc0CJ1k9H6iNatESqW2zBoIr2bntS5obCxeU+1Q\n"
                            "gJslCVBgpCs9oPHwZW55YtiMNATydJp72FbzhCQw4iSzZqqH+OsN06QcDzPfRPor\n"
                            "b4dhHuwDYgB3ILSvndCHJB1eMfmtxKsBNdqWcxuYtgZRQ4Paih3PJscdm3FG/U/E\n"
                            "vCjibV6ppk1wpiJaOrTLCHZ477BaVxF3t/tggt8SdT7a5UczxlLggNWgvIbvSnLh\n"
                            "kT33vQsaVIXm4viZGS2vF2J3nsSXBq7p5b522vXNfQKCAQBm+g7QPY17LbgSB7Zw\n"
                            "dE4xJvmXOZWFf9bkvlEQLUec4QWCGiX/o1uq35UGhYaHbPXl2mIw+qH8lHOeKksL\n"
                            "+gkT71ODB1IT0V+TnANm16ojxFE8ITYPefan/P42B1s2kvB3x4dva2o8xapaJ3ut\n"
                            "WwSjFrZPBxsH8vkvma1cNXXaYlMUN7fevZ0rTrReaImk04KX8rhbUo4j3mth0ldT\n"
                            "nbpiJnXIBpmkfKaUxnsY02qu4BWzNrvrh49Q/1W+gj7Lzp5ey008mCQlw9VL6naI\n"
                            "XmC26QQXrrtf8QSm42uKftJelYK5teBU+Goo6ewUpVA+a1Tsi/BIJWcn2OCjPjil\n"
                            "hVKJAoIBAAvea0t/vSJMOa4Nlu9+aOYQJOfzoP/MUw2BiFtDYEhWL6bE9Ylh5+dU\n"
                            "W6Ci/HDRkdvLlUDDCRJIkFZZ2NG0oIxwDxppvYUEzQ0Xmli15CUkuFNuWz9bjsxw\n"
                            "DmaO8svBuz2Z+hX9AQyZ34S+2G+0uoBCfhe4KMg2EyTUJxQjzplFa5SIRF1jqUpi\n"
                            "cQzPee5FZ0mvs4M268tMSMUNoToJzNv/RO8LuYXJGnZ3Erfyt9VzNvnvK0JcGAZS\n"
                            "6ubTWgIz6j/a9O0welLYujn3LCy+sy4yAAMzEF4eKfigXGmnmiNxS/Z+gYmAueHw\n"
                            "gVpE3XkeysCQ2ppD9pDqNZqq6kv77xkCggEBAKYLQXIxtLCxy2Hi7wV+9j+aKyrL\n"
                            "gImTqHWTsFjkIukR92IeBFm6VQb55zI28Uwx964enaeekceaobqejatKrJKrlzJW\n"
                            "8fJ3of5sXPkWu6blW+xIWWqanswn5eG2pLaXfmR9tIiBBL3STpLYcNpcggW3K1f/\n"
                            "MU8l1g1z5qbOSFQVIAa8MTJ48zR6B3Kbdu7oYmV0P18IWSTxgATHnIXfLeSwrC5/\n"
                            "A78vHSfGPirZAPIAFz56vVNCxyX7GuUoSRKV0P4sjmny7BnWX/K+1ntR8H728wi3\n"
                            "g07vzLFefg7gINFqelEptjg/pXDqHv6K2YW28fpavuv4yMHticseFGGWbLE=\n"
                            "-----END RSA PRIVATE KEY-----\n";

    size_t key_size;
    BYTE *key_bytes = _pem_2_bytes(private_pem, &key_size);

    char *produced_bytes_hex = _bytes_2_hex(key_bytes, key_size);

    char *expected_bytes_hex = "308209280201000282020100973a889b9fcc18f97a5991bfd14d89f037cffa972e92333d3c498a89c2902ecd29420b2fee2d9f6567756c3d3c3e1beb56c445e4b8be36b281c14b9fe2cfd129966a06f023053066b530ec888432fe359b7e2589620ab4aedc3d0e8cfdd9c9417b8bfc02beca7fcaf7151fa01c595125207b02fb57af91e068aa1344a36241b4be9983f3ebbace4fb85e539b0dff868ee74815456619a527b694a374a87fe2429678445ba2bddfe93b935c74e4115620b6a04ddb9f0dc78ee4dc44de8e57338c2d60741a29c00de8867ec035efeb81248d3090b4d389667aa0ae7b7f471d9bd01665bcc58d08a49bd7f181b8b5af8cd52162e14b7dbe8985276ea4c2070725d3effb7b347db96842700025faaa3b03d4ec99b9c9b936f017c74cfd50a6bf1f30433130658839c451283e3d54526183ba1e0922f7fd982e37c6d6c29f43b9d37d81eb8a2f8fc39d8f71e4dd2ae5fda98ccf3100124f39d05e15fcfafc8681b7679cba5e5313dea8c735be895198fafae00b0d1ae579420ea5b3f77f22f62caa8627a7fa33978006de7b834f099dfde73cd12cccd09dbf3f935b7388a88c69f3bbe1d3038ac56b24c5ab6bdc8dffafed36d6996f0dcc2b4b1c279b3c2a508a0e3e5cc8c9c8b7b60e26a037063a7597a7f5b1c618f83fd214e898accc186aaf5f225072fbd04040d8eb8a9db0aab16c97537a800f79c500fc2d82936ca6bb1a65e502030100010282020000a72d0dd6fbcfa3cc2674ddaa2eb688c604ece5183b6363414e63fdc24c531769b5324d2baf20c014594a755d3c3b6ca1bc493cfa9b3fab37aa390460bb5b00ddf8693d423974830d07400e3adbe9831bbfc8b3b62babaa11a365dbb000efc08ba3081c8eec5aeeea7039e9bc159aa71963ce987d4171d4d13ee2c46a1c33826f4c44689a3cfd4514dbbb6ab0fdc87bf77db531ce860fd38313533d5eb8e6a638f61dfd734f7497123dc9a96b8eb39b828e60a7b121231a77dc87a39a63c0023bf3edac6b3fbc0fa3fd0a21717ec7d8fb8f1920dec4fa1f4f70517234416979d58eece8c17a2713d133e6c6806a58a656f591597d1a848781ab15a50cd8b80e1788ece1bd3ab4dfcfa138f28d784c35b7b5a93de79abf08efb99570b92cb18a6118deceb8cf0ea7b27d4ba0ca872722d9ac9cc193c9f514fdc2dc2b79d2f94ddb60ef36c86dacd45cca2d815e5d6c644b48ddad8fa8418d2cd731e9279c95b3c40dda136dca8b998046f719290020d1ffcab6a69de5486670f7ed68b70e7e94ab5651252c76884d1fa5c6fa7799df39d17e18a042de79f15efd7db3be860b6b0851d09c52795d0bb2e36dc9e8c42dac56a782381669d6d7a888d2c7f92de9db29ad2553acc8d929392e3f6ce0e032726ae7d941d52ba6786f0541a6d4d3c5e5c19ba42fb5a5eecbe5faa5087661548dc308504880def491b756daf2093ec2a10282010100cb90a28bb0925945e24cd479d9d44cbc1c87ac520ab9e78e4f206c17dce91f21a19e21aee38a5096131a56fb79b5d218b74945b31500c224ed5366f6ba6d6cfa28616fa3df50968216aef3cc694d3c8cca87b8aaef3c7861d115835619831fe81d47ec19c03f12a9abe892241919e41c1a2c12e9f078d09ec7917665a7e12c68c7c439638f75787d6e791211779117e4f8380813ca4c72e7822af639b25f98772b3fc723c9b184a52a1196d6ea996339176e1fa31becf6f2585fabecdc2dd8eddf598cb68dab5e5e1f062eebc484baf04caf59f907160883940cd63f69fcf005d11f70a34a8b47561738263fbe0dd19649b7fe3d76802cf8cca0c22fb40086890282010100be2ec4283fa1fd54bf6c3ce6a7d475f3cc1c0c0d141e6091d3f8db1ee74f7934f3aaa9c48f2cc55dc75a11b0736827398b6b5906e734089d64f47ea235ab444aa5b6cc1a08af66e7b52e686c2c5e53ed50809b25095060a42b3da0f1f0656e7962d88c3404f2749a7bd856f3842430e224b366aa87f8eb0dd3a41c0f33df44fa2b6f87611eec0362007720b4af9dd087241d5e31f9adc4ab0135da96731b98b606514383da8a1dcf26c71d9b7146fd4fc4bc28e26d5ea9a64d70a6225a3ab4cb087678efb05a571177b7fb6082df12753edae54733c652e080d5a0bc86ef4a72e1913df7bd0b1a5485e6e2f899192daf1762779ec49706aee9e5be76daf5cd7d0282010066fa0ed03d8d7b2db81207b670744e3126f9973995857fd6e4be51102d479ce105821a25ffa35baadf95068586876cf5e5da6230faa1fc94739e2a4b0bfa0913ef5383075213d15f939c0366d7aa23c4513c21360f79f6a7fcfe36075b3692f077c7876f6b6a3cc5aa5a277bad5b04a316b64f071b07f2f92f99ad5c3575da62531437b7debd9d2b4eb45e6889a4d38297f2b85b528e23de6b61d257539dba622675c80699a47ca694c67b18d36aaee015b336bbeb878f50ff55be823ecbce9e5ecb4d3c982425c3d54bea76885e60b6e90417aebb5ff104a6e36b8a7ed25e9582b9b5e054f86a28e9ec14a5503e6b54ec8bf048256727d8e0a33e38a5855289028201000bde6b4b7fbd224c39ae0d96ef7e68e61024e7f3a0ffcc530d81885b436048562fa6c4f58961e7e7545ba0a2fc70d191dbcb9540c3091248905659d8d1b4a08c700f1a69bd8504cd0d179a58b5e42524b8536e5b3f5b8ecc700e668ef2cbc1bb3d99fa15fd010c99df84bed86fb4ba80427e17b828c8361324d4271423ce99456b9488445d63a94a62710ccf79ee456749afb38336ebcb4c48c50da13a09ccdbff44ef0bb985c91a767712b7f2b7d57336f9ef2b425c180652eae6d35a0233ea3fdaf4ed307a52d8ba39f72c2cbeb32e32000333105e1e29f8a05c69a79a23714bf67e818980b9e1f0815a44dd791ecac090da9a43f690ea359aaaea4bfbef190282010100a60b417231b4b0b1cb61e2ef057ef63f9a2b2acb808993a87593b058e422e911f7621e0459ba5506f9e73236f14c31f7ae1e9da79e91c79aa1ba9e8dab4aac92ab973256f1f277a1fe6c5cf916bba6e55bec48596a9a9ecc27e5e1b6a4b6977e647db4888104bdd24e92d870da5c8205b72b57ff314f25d60d73e6a6ce4854152006bc313278f3347a07729b76eee86265743f5f085924f18004c79c85df2de4b0ac2e7f03bf2f1d27c63e2ad900f200173e7abd5342c725fb1ae528491295d0fe2c8e69f2ec19d65ff2bed67b51f07ef6f308b7834eefccb15e7e0ee020d16a7a5129b6383fa570ea1efe8ad985b6f1fa5abeebf8c8c1ed89cb1e1461966cb1";
  
    TEST_ASSERT_EQUAL_STRING(expected_bytes_hex, produced_bytes_hex);
}


void test_bytes_2_pem_convertion_private()
{
    char *bytes_hex = "308209280201000282020100973a889b9fcc18f97a5991bfd14d89f037cffa972e92333d3c498a89c2902ecd29420b2fee2d9f6567756c3d3c3e1beb56c445e4b8be36b281c14b9fe2cfd129966a06f023053066b530ec888432fe359b7e2589620ab4aedc3d0e8cfdd9c9417b8bfc02beca7fcaf7151fa01c595125207b02fb57af91e068aa1344a36241b4be9983f3ebbace4fb85e539b0dff868ee74815456619a527b694a374a87fe2429678445ba2bddfe93b935c74e4115620b6a04ddb9f0dc78ee4dc44de8e57338c2d60741a29c00de8867ec035efeb81248d3090b4d389667aa0ae7b7f471d9bd01665bcc58d08a49bd7f181b8b5af8cd52162e14b7dbe8985276ea4c2070725d3effb7b347db96842700025faaa3b03d4ec99b9c9b936f017c74cfd50a6bf1f30433130658839c451283e3d54526183ba1e0922f7fd982e37c6d6c29f43b9d37d81eb8a2f8fc39d8f71e4dd2ae5fda98ccf3100124f39d05e15fcfafc8681b7679cba5e5313dea8c735be895198fafae00b0d1ae579420ea5b3f77f22f62caa8627a7fa33978006de7b834f099dfde73cd12cccd09dbf3f935b7388a88c69f3bbe1d3038ac56b24c5ab6bdc8dffafed36d6996f0dcc2b4b1c279b3c2a508a0e3e5cc8c9c8b7b60e26a037063a7597a7f5b1c618f83fd214e898accc186aaf5f225072fbd04040d8eb8a9db0aab16c97537a800f79c500fc2d82936ca6bb1a65e502030100010282020000a72d0dd6fbcfa3cc2674ddaa2eb688c604ece5183b6363414e63fdc24c531769b5324d2baf20c014594a755d3c3b6ca1bc493cfa9b3fab37aa390460bb5b00ddf8693d423974830d07400e3adbe9831bbfc8b3b62babaa11a365dbb000efc08ba3081c8eec5aeeea7039e9bc159aa71963ce987d4171d4d13ee2c46a1c33826f4c44689a3cfd4514dbbb6ab0fdc87bf77db531ce860fd38313533d5eb8e6a638f61dfd734f7497123dc9a96b8eb39b828e60a7b121231a77dc87a39a63c0023bf3edac6b3fbc0fa3fd0a21717ec7d8fb8f1920dec4fa1f4f70517234416979d58eece8c17a2713d133e6c6806a58a656f591597d1a848781ab15a50cd8b80e1788ece1bd3ab4dfcfa138f28d784c35b7b5a93de79abf08efb99570b92cb18a6118deceb8cf0ea7b27d4ba0ca872722d9ac9cc193c9f514fdc2dc2b79d2f94ddb60ef36c86dacd45cca2d815e5d6c644b48ddad8fa8418d2cd731e9279c95b3c40dda136dca8b998046f719290020d1ffcab6a69de5486670f7ed68b70e7e94ab5651252c76884d1fa5c6fa7799df39d17e18a042de79f15efd7db3be860b6b0851d09c52795d0bb2e36dc9e8c42dac56a782381669d6d7a888d2c7f92de9db29ad2553acc8d929392e3f6ce0e032726ae7d941d52ba6786f0541a6d4d3c5e5c19ba42fb5a5eecbe5faa5087661548dc308504880def491b756daf2093ec2a10282010100cb90a28bb0925945e24cd479d9d44cbc1c87ac520ab9e78e4f206c17dce91f21a19e21aee38a5096131a56fb79b5d218b74945b31500c224ed5366f6ba6d6cfa28616fa3df50968216aef3cc694d3c8cca87b8aaef3c7861d115835619831fe81d47ec19c03f12a9abe892241919e41c1a2c12e9f078d09ec7917665a7e12c68c7c439638f75787d6e791211779117e4f8380813ca4c72e7822af639b25f98772b3fc723c9b184a52a1196d6ea996339176e1fa31becf6f2585fabecdc2dd8eddf598cb68dab5e5e1f062eebc484baf04caf59f907160883940cd63f69fcf005d11f70a34a8b47561738263fbe0dd19649b7fe3d76802cf8cca0c22fb40086890282010100be2ec4283fa1fd54bf6c3ce6a7d475f3cc1c0c0d141e6091d3f8db1ee74f7934f3aaa9c48f2cc55dc75a11b0736827398b6b5906e734089d64f47ea235ab444aa5b6cc1a08af66e7b52e686c2c5e53ed50809b25095060a42b3da0f1f0656e7962d88c3404f2749a7bd856f3842430e224b366aa87f8eb0dd3a41c0f33df44fa2b6f87611eec0362007720b4af9dd087241d5e31f9adc4ab0135da96731b98b606514383da8a1dcf26c71d9b7146fd4fc4bc28e26d5ea9a64d70a6225a3ab4cb087678efb05a571177b7fb6082df12753edae54733c652e080d5a0bc86ef4a72e1913df7bd0b1a5485e6e2f899192daf1762779ec49706aee9e5be76daf5cd7d0282010066fa0ed03d8d7b2db81207b670744e3126f9973995857fd6e4be51102d479ce105821a25ffa35baadf95068586876cf5e5da6230faa1fc94739e2a4b0bfa0913ef5383075213d15f939c0366d7aa23c4513c21360f79f6a7fcfe36075b3692f077c7876f6b6a3cc5aa5a277bad5b04a316b64f071b07f2f92f99ad5c3575da62531437b7debd9d2b4eb45e6889a4d38297f2b85b528e23de6b61d257539dba622675c80699a47ca694c67b18d36aaee015b336bbeb878f50ff55be823ecbce9e5ecb4d3c982425c3d54bea76885e60b6e90417aebb5ff104a6e36b8a7ed25e9582b9b5e054f86a28e9ec14a5503e6b54ec8bf048256727d8e0a33e38a5855289028201000bde6b4b7fbd224c39ae0d96ef7e68e61024e7f3a0ffcc530d81885b436048562fa6c4f58961e7e7545ba0a2fc70d191dbcb9540c3091248905659d8d1b4a08c700f1a69bd8504cd0d179a58b5e42524b8536e5b3f5b8ecc700e668ef2cbc1bb3d99fa15fd010c99df84bed86fb4ba80427e17b828c8361324d4271423ce99456b9488445d63a94a62710ccf79ee456749afb38336ebcb4c48c50da13a09ccdbff44ef0bb985c91a767712b7f2b7d57336f9ef2b425c180652eae6d35a0233ea3fdaf4ed307a52d8ba39f72c2cbeb32e32000333105e1e29f8a05c69a79a23714bf67e818980b9e1f0815a44dd791ecac090da9a43f690ea359aaaea4bfbef190282010100a60b417231b4b0b1cb61e2ef057ef63f9a2b2acb808993a87593b058e422e911f7621e0459ba5506f9e73236f14c31f7ae1e9da79e91c79aa1ba9e8dab4aac92ab973256f1f277a1fe6c5cf916bba6e55bec48596a9a9ecc27e5e1b6a4b6977e647db4888104bdd24e92d870da5c8205b72b57ff314f25d60d73e6a6ce4854152006bc313278f3347a07729b76eee86265743f5f085924f18004c79c85df2de4b0ac2e7f03bf2f1d27c63e2ad900f200173e7abd5342c725fb1ae528491295d0fe2c8e69f2ec19d65ff2bed67b51f07ef6f308b7834eefccb15e7e0ee020d16a7a5129b6383fa570ea1efe8ad985b6f1fa5abeebf8c8c1ed89cb1e1461966cb1";

    BYTE *bytes;
    _hex_2_bytes(bytes_hex, bytes, strlen(bytes_hex) / 2);

    size_t pem_size;
    char *produced_pem = _bytes_2_pem(bytes, strlen(bytes_hex) / 2, &pem_size, 0);


    char *expected_pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                            "MIIJKAIBAAKCAgEAlzqIm5/MGPl6WZG/0U2J8DfP+pcukjM9PEmKicKQLs0pQgsv\n"
                            "7i2fZWd1bD08PhvrVsRF5Li+NrKBwUuf4s/RKZZqBvAjBTBmtTDsiIQy/jWbfiWJ\n"
                            "Ygq0rtw9Doz92clBe4v8Ar7Kf8r3FR+gHFlRJSB7AvtXr5HgaKoTRKNiQbS+mYPz\n"
                            "67rOT7heU5sN/4aO50gVRWYZpSe2lKN0qH/iQpZ4RFuivd/pO5NcdOQRViC2oE3b\n"
                            "nw3HjuTcRN6OVzOMLWB0GinADeiGfsA17+uBJI0wkLTTiWZ6oK57f0cdm9AWZbzF\n"
                            "jQikm9fxgbi1r4zVIWLhS32+iYUnbqTCBwcl0+/7ezR9uWhCcAAl+qo7A9TsmbnJ\n"
                            "uTbwF8dM/VCmvx8wQzEwZYg5xFEoPj1UUmGDuh4JIvf9mC43xtbCn0O5032B64ov\n"
                            "j8Odj3Hk3Srl/amMzzEAEk850F4V/Pr8hoG3Z5y6XlMT3qjHNb6JUZj6+uALDRrl\n"
                            "eUIOpbP3fyL2LKqGJ6f6M5eABt57g08Jnf3nPNEszNCdvz+TW3OIqIxp87vh0wOK\n"
                            "xWskxatr3I3/r+021plvDcwrSxwnmzwqUIoOPlzIyci3tg4moDcGOnWXp/Wxxhj4\n"
                            "P9IU6JiszBhqr18iUHL70EBA2OuKnbCqsWyXU3qAD3nFAPwtgpNsprsaZeUCAwEA\n"
                            "AQKCAgAApy0N1vvPo8wmdN2qLraIxgTs5Rg7Y2NBTmP9wkxTF2m1Mk0rryDAFFlK\n"
                            "dV08O2yhvEk8+ps/qzeqOQRgu1sA3fhpPUI5dIMNB0AOOtvpgxu/yLO2K6uqEaNl\n"
                            "27AA78CLowgcjuxa7upwOem8FZqnGWPOmH1BcdTRPuLEahwzgm9MRGiaPP1FFNu7\n"
                            "arD9yHv3fbUxzoYP04MTUz1euOamOPYd/XNPdJcSPcmpa46zm4KOYKexISMad9yH\n"
                            "o5pjwAI78+2saz+8D6P9CiFxfsfY+48ZIN7E+h9PcFFyNEFpedWO7OjBeicT0TPm\n"
                            "xoBqWKZW9ZFZfRqEh4GrFaUM2LgOF4js4b06tN/PoTjyjXhMNbe1qT3nmr8I77mV\n"
                            "cLkssYphGN7OuM8Op7J9S6DKhyci2aycwZPJ9RT9wtwredL5Tdtg7zbIbazUXMot\n"
                            "gV5dbGRLSN2tj6hBjSzXMeknnJWzxA3aE23Ki5mARvcZKQAg0f/Ktqad5UhmcPft\n"
                            "aLcOfpSrVlElLHaITR+lxvp3md850X4YoELeefFe/X2zvoYLawhR0JxSeV0LsuNt\n"
                            "yejELaxWp4I4FmnW16iI0sf5LenbKa0lU6zI2Sk5Lj9s4OAycmrn2UHVK6Z4bwVB\n"
                            "ptTTxeXBm6QvtaXuy+X6pQh2YVSNwwhQSIDe9JG3VtryCT7CoQKCAQEAy5Cii7CS\n"
                            "WUXiTNR52dRMvByHrFIKueeOTyBsF9zpHyGhniGu44pQlhMaVvt5tdIYt0lFsxUA\n"
                            "wiTtU2b2um1s+ihhb6PfUJaCFq7zzGlNPIzKh7iq7zx4YdEVg1YZgx/oHUfsGcA/\n"
                            "Eqmr6JIkGRnkHBosEunweNCex5F2ZafhLGjHxDljj3V4fW55EhF3kRfk+DgIE8pM\n"
                            "cueCKvY5sl+Ydys/xyPJsYSlKhGW1uqZYzkXbh+jG+z28lhfq+zcLdjt31mMto2r\n"
                            "Xl4fBi7rxIS68EyvWfkHFgiDlAzWP2n88AXRH3CjSotHVhc4Jj++DdGWSbf+PXaA\n"
                            "LPjMoMIvtACGiQKCAQEAvi7EKD+h/VS/bDzmp9R188wcDA0UHmCR0/jbHudPeTTz\n"
                            "qqnEjyzFXcdaEbBzaCc5i2tZBuc0CJ1k9H6iNatESqW2zBoIr2bntS5obCxeU+1Q\n"
                            "gJslCVBgpCs9oPHwZW55YtiMNATydJp72FbzhCQw4iSzZqqH+OsN06QcDzPfRPor\n"
                            "b4dhHuwDYgB3ILSvndCHJB1eMfmtxKsBNdqWcxuYtgZRQ4Paih3PJscdm3FG/U/E\n"
                            "vCjibV6ppk1wpiJaOrTLCHZ477BaVxF3t/tggt8SdT7a5UczxlLggNWgvIbvSnLh\n"
                            "kT33vQsaVIXm4viZGS2vF2J3nsSXBq7p5b522vXNfQKCAQBm+g7QPY17LbgSB7Zw\n"
                            "dE4xJvmXOZWFf9bkvlEQLUec4QWCGiX/o1uq35UGhYaHbPXl2mIw+qH8lHOeKksL\n"
                            "+gkT71ODB1IT0V+TnANm16ojxFE8ITYPefan/P42B1s2kvB3x4dva2o8xapaJ3ut\n"
                            "WwSjFrZPBxsH8vkvma1cNXXaYlMUN7fevZ0rTrReaImk04KX8rhbUo4j3mth0ldT\n"
                            "nbpiJnXIBpmkfKaUxnsY02qu4BWzNrvrh49Q/1W+gj7Lzp5ey008mCQlw9VL6naI\n"
                            "XmC26QQXrrtf8QSm42uKftJelYK5teBU+Goo6ewUpVA+a1Tsi/BIJWcn2OCjPjil\n"
                            "hVKJAoIBAAvea0t/vSJMOa4Nlu9+aOYQJOfzoP/MUw2BiFtDYEhWL6bE9Ylh5+dU\n"
                            "W6Ci/HDRkdvLlUDDCRJIkFZZ2NG0oIxwDxppvYUEzQ0Xmli15CUkuFNuWz9bjsxw\n"
                            "DmaO8svBuz2Z+hX9AQyZ34S+2G+0uoBCfhe4KMg2EyTUJxQjzplFa5SIRF1jqUpi\n"
                            "cQzPee5FZ0mvs4M268tMSMUNoToJzNv/RO8LuYXJGnZ3Erfyt9VzNvnvK0JcGAZS\n"
                            "6ubTWgIz6j/a9O0welLYujn3LCy+sy4yAAMzEF4eKfigXGmnmiNxS/Z+gYmAueHw\n"
                            "gVpE3XkeysCQ2ppD9pDqNZqq6kv77xkCggEBAKYLQXIxtLCxy2Hi7wV+9j+aKyrL\n"
                            "gImTqHWTsFjkIukR92IeBFm6VQb55zI28Uwx964enaeekceaobqejatKrJKrlzJW\n"
                            "8fJ3of5sXPkWu6blW+xIWWqanswn5eG2pLaXfmR9tIiBBL3STpLYcNpcggW3K1f/\n"
                            "MU8l1g1z5qbOSFQVIAa8MTJ48zR6B3Kbdu7oYmV0P18IWSTxgATHnIXfLeSwrC5/\n"
                            "A78vHSfGPirZAPIAFz56vVNCxyX7GuUoSRKV0P4sjmny7BnWX/K+1ntR8H728wi3\n"
                            "g07vzLFefg7gINFqelEptjg/pXDqHv6K2YW28fpavuv4yMHticseFGGWbLE=\n"
                            "-----END RSA PRIVATE KEY-----\n";

    TEST_ASSERT_EQUAL_STRING(expected_pem, produced_pem);
}


void test_generate_keys_convert_check()
{
    KEYS_PAIR rsa_pem_keys = _init_rsa_keys();

    size_t key_size;
    BYTE *key_bytes = _pem_2_bytes(rsa_pem_keys.public.pem_key, &key_size);

    char *produced_bytes_hex = _bytes_2_hex(key_bytes, key_size);

    size_t pem_size;
    char *produced_pem = _bytes_2_pem(key_bytes, key_size, &pem_size, 1);

    //printf("Orig: %s\nProduced: %s\n", rsa_pem_keys.private.pem_key, produced_pem);

    TEST_ASSERT_EQUAL_STRING(rsa_pem_keys.public.pem_key, produced_pem);
}



int main(void)
{
    UNITY_BEGIN();
    
    RUN_TEST(test_sha512_1);
    RUN_TEST(test_sha512_2);

    RUN_TEST(test_rsa4096_sign_1);
    RUN_TEST(test_rsa4096_sign_2);

    RUN_TEST(test_rsa4096_verify_1);
    RUN_TEST(test_rsa4096_verify_2);

    RUN_TEST(test_init_rsa_keys);

    RUN_TEST(test_base64_2_bytes_convertion);
    RUN_TEST(test_bytes_2_base64_convertion);

    RUN_TEST(test_pem_2_bytes_convertion_public);
    RUN_TEST(test_bytes_2_pem_convertion_public);

    RUN_TEST(test_pem_2_bytes_convertion_private);
    RUN_TEST(test_bytes_2_pem_convertion_private);

    RUN_TEST(test_generate_keys_convert_check);

    UNITY_END();
    
    return 0;   
}