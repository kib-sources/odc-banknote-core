#include "unity.c"
#include "common.h"


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
    
    UNITY_END();
    
    return 0;   
}