/**
    @file openssl_rsa.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include "openssl_rsa.h"

int32_t openssl_rsa_msg_encrypt(char *rsa_pubkey_path, const unsigned char *plain_msg, int plain_msg_size, unsigned char *cipher_msg, int *cipher_msg_size)
{

    FILE* fp;
    RSA *rsa_pubkey;
    int32_t ret = ERROR_;
    fp = fopen(rsa_pubkey_path,"r");
    if(!fp) return (ret);

    rsa_pubkey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if(!rsa_pubkey) return (ret);

    *cipher_msg_size = RSA_public_encrypt(plain_msg_size, plain_msg, cipher_msg, rsa_pubkey, RSA_PKCS1_PADDING);

    RSA_free(rsa_pubkey);
    
    return (ret);
}

int32_t openssl_rsa_msg_decrypt(char *rsa_privkey_path, const unsigned char *cipher_msg, int cipher_msg_size, unsigned char *plain_msg, int *plain_msg_size)
{

    FILE* fp;
    RSA *rsa_privkey;
    int32_t ret = ERROR_;
    fp = fopen("rsa_privkey.pem","r");
    if(!fp) return (ret);

    rsa_privkey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if(!rsa_privkey) return ret;
    
    *plain_msg_size = RSA_private_decrypt(cipher_msg_size, cipher_msg, plain_msg, rsa_privkey, RSA_PKCS1_PADDING);

    RSA_free(rsa_privkey);

    return (ret);
}

int32_t openssl_rsa_keypair_gen(void) 
{
    RSA *rsa_key;
    int32_t ret = ERROR_;
    
    if(RAND_status())
    {
        rsa_key = RSA_new();
        if(!rsa_key) return ret;
    
#if (OPENSSL_111 == ENABLED)
        RSA_generate_key_ex(rsa_key, 1024, (BIGNUM *)3, NULL);
#elif (OPENSSL_102 == ENABLED)
        rsa_key = RSA_generate_key(1024,3,NULL,NULL);
#endif // OPENSSL_111

        if(RSA_check_key(rsa_key) == RSA_KEY_VALID) 
            ret = SUCCESS_;

        do
        {
            FILE* fp;

            fp = fopen("rsa_privkey.pem", "w");
            if(!fp) return (ret);

            PEM_write_RSAPrivateKey(fp, rsa_key, NULL, NULL, 0, 0, NULL);
            fclose(fp);

            fp = fopen("rsa_pubkey.pem", "w");
            if(!fp) return (ret);

            PEM_write_RSA_PUBKEY(fp, rsa_key);
            fclose(fp);
        }while(0);
        
        RSA_free(rsa_key);
    }

    return (ret);
}

