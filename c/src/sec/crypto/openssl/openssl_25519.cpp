/**
    @file openssl_25519.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#if (OPENSSL_111 == ENABLED)
void openssl_111_print_25519_prikey(EVP_PKEY *p_pkey)
{
    int32_t prikey_size = X25519_PRIVATE_KEY_LEN_;
    uint8_t tmp_prikey[X25519_PRIVATE_KEY_LEN_];
    uint8_t *p_tmp_prikey = tmp_prikey;

    EVP_PKEY_get_raw_private_key(p_pkey, p_tmp_prikey, (size_t *)&prikey_size);
    DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"openssl 25519_prikey", p_tmp_prikey, prikey_size);
}

void openssl_111_print_25519_pubkey(EVP_PKEY *p_pkey)
{
    int32_t pubkey_size = X25519_PUBLIC_KEY_LEN_;
    uint8_t tmp_pubkey[X25519_PUBLIC_KEY_LEN_];
    uint8_t *p_tmp_pubkey = tmp_pubkey;

    EVP_PKEY_get_raw_public_key(p_pkey, p_tmp_pubkey, (size_t *)&pubkey_size);
    DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"openssl 25519_pubkey", p_tmp_pubkey, pubkey_size);
}

int32_t openssl_111_get_25519_prikey(EVP_PKEY *p_pkey, uint8_t *p_prikey)
{
    int32_t ret;
    int32_t prikey_size = X25519_PRIVATE_KEY_LEN_;
    uint8_t tmp_prikey[X25519_PRIVATE_KEY_LEN_];
    uint8_t *p_tmp_prikey = tmp_prikey;

    ret = EVP_PKEY_get_raw_private_key(p_pkey, p_tmp_prikey, (size_t *)&prikey_size);
    if (ret == 1)
    {
        ASSERT_M(X25519_PRIVATE_KEY_LEN_ == prikey_size);
        MEMCPY_M(p_prikey, p_tmp_prikey, prikey_size);
        DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"openssl 25519_prikey", p_prikey, prikey_size);
    }
    else
    {
        DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"Error : (%s)\n",  __FUNCTION__);
        prikey_size = 0;
    }
    
    return (prikey_size);
}

int32_t openssl_111_get_25519_pubkey(EVP_PKEY *p_pkey, uint8_t *p_pubkey)
{
    int32_t ret;
    int32_t pubkey_size = X25519_PUBLIC_KEY_LEN_;
    uint8_t tmp_pubkey[X25519_PUBLIC_KEY_LEN_];
    uint8_t *p_tmp_pubkey = tmp_pubkey;

    ret = EVP_PKEY_get_raw_public_key(p_pkey, p_tmp_pubkey, (size_t *)&pubkey_size);
    if (ret == 1)
    {
        ASSERT_M(X25519_PRIVATE_KEY_LEN_ == pubkey_size);
        MEMCPY_M(p_pubkey, p_tmp_pubkey, X25519_PUBLIC_KEY_LEN_);
        DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"openssl 25519_pubkey", p_pubkey, pubkey_size);
    }
    else
    {
        DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"Error : (%s)\n",  __FUNCTION__);
        pubkey_size = 0;
    }
    
    return (pubkey_size);
}

int32_t openssl_111_25519_keygen(char *p_path, int32_t type)
{
    int32_t ret = ERROR_;
    EVP_PKEY_CTX *pctx;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

    pctx = EVP_PKEY_CTX_new_id(type, NULL);
    if (!pctx)
    {
        DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"ERROR : pctx\n");
        get_current_rss_monitor(DBG_INFO, (char *)"2");
        return (ret);
    }

    do
    {
        EVP_PKEY *pkey = NULL;
        
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);

        if (!pkey)
        {
            break;
        }

        do
        {
            if (p_path)
            {
                char pubkey_dir[SSL_PATH_SIZE];
                char prikey_dir[SSL_PATH_SIZE];
                
                sprintf(pubkey_dir, "%s%s", p_path, (char *)"ed_pubkey.pem");
                sprintf(prikey_dir, "%s%s", p_path, (char *)"ed_privkey.pem");

                // ED Private Key
                PEM_new_write_PRIKEY(prikey_dir, pkey);
                
                // ED Public Key
                PEM_new_write_PUBKEY(pubkey_dir, pkey);
            }
            else
            {
                PEM_new_write_PUBKEY((char *)"ed_pubkey.pem", pkey);
                PEM_new_write_PRIKEY((char *)"ed_privkey.pem", pkey);
            }

        } while (0);

        EVP_PKEY_free(pkey);
    } while (0);

    EVP_PKEY_CTX_free(pctx);

    get_current_rss_monitor(DBG_INFO, (char *)"2");

    return (ret);
}
#endif // OPENSSL_111

