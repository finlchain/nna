/**
    @file openssl_ed25519.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#if (OPENSSL_111 == ENABLED)
int32_t openssl_111_ed25519_sign(bool b_enc, char *p_prikey_path, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex)
{
    int32_t ret = ERROR_;
    EVP_PKEY *p_pkey = NULL;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

    p_pkey = EVP_PKEY_new_read_PRIKEY(b_enc, p_prikey_path);
    if (!p_pkey)
    {
        DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"ERROR : prikey parse\n");
        return (ret);
    }

    openssl_111_print_25519_prikey(p_pkey);
    openssl_111_print_25519_pubkey(p_pkey);

    do
    {
        EVP_MD_CTX *p_mdctx = NULL;
        uint8_t hash[HASH_SIZE];
        
        openssl_sha256(hash, (uint8_t *)p_data, data_len);
        
        DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"msg hash", hash, HASH_SIZE);
        
        p_mdctx = EVP_MD_CTX_new();
        if (!p_mdctx) 
        {
            DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"Failed to create md ctx : OpenSSL %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        
        do
        {
            if(EVP_DigestSignInit(p_mdctx, NULL, NULL, NULL, p_pkey) != 1) 
            {
                DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"Failed to DigestSignInit : OpenSSL %s\n", ERR_error_string(ERR_get_error(), NULL));
                break;
            }

            do
            {
                size_t sig_len = SIG_SIZE;
                
                if(EVP_DigestSign(p_mdctx, p_sig_hex->sig, &sig_len, hash, HASH_SIZE) != 1)
                {
                    DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"Failed to sign a message : OpenSSL %s\n", ERR_error_string(ERR_get_error(), NULL));
                    break;
                }
                
                DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"ed sig", p_sig_hex->sig, sig_len);

                ret = SUCCESS_;
            } while(0);
        } while(0);
        
        EVP_MD_CTX_free(p_mdctx);
    } while (0);

    EVP_PKEY_free(p_pkey);

    get_current_rss_monitor(DBG_INFO, (char *)"2");

    return (ret);
}

int32_t openssl_111_ed25519_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
    EVP_PKEY *p_pkey;
    
    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    p_pkey = EVP_PKEY_new_raw_public_key(NID_ED25519, NULL, p_pubkey, ED25519_PUBLIC_KEY_LEN_);
    if (!p_pkey)
    {
        DBG_PRINT(DBG_CLI, DBG_ERROR, (void *)"ERROR : p_pkey\n"); 
        get_current_rss_monitor(DBG_NONE, (char *)"2");
        return (ret);
    }

    do
    {
        EVP_MD_CTX *p_mdctx = EVP_MD_CTX_new();

        if(!p_mdctx)
        {
            break;
        }

        do
        {
            if (EVP_DigestVerifyInit(p_mdctx, NULL, NULL, NULL, p_pkey) == 1)
            {
                if (EVP_DigestVerify(p_mdctx, p_sig_hex->sig, SIG_SIZE, p_data, data_len) == 1)
                {
                    ret = SUCCESS_;
                    DBG_PRINT(DBG_CLI, DBG_INFO, (void *)"Signature verified.\n");
                }
                else
                {
                    DBG_PRINT(DBG_CLI, DBG_ERROR, (void *)"Signature did not verify.\n"); 
                }
            }
        } while (0);
        
        EVP_MD_CTX_free(p_mdctx);
    } while (0);
    
    EVP_PKEY_free(p_pkey);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (ret);
}

#endif // OPENSSL_111

int32_t openssl_ed_pubkey_pem2hex(char *p_pubkey_path, uint8_t *p_pubkey)

{
    int32_t ret = ERROR_;

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_pkey;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    p_pkey = EVP_PKEY_new_read_PUBKEY(p_pubkey_path);
    if (p_pkey)
    {
        int32_t pubkey_size = X25519_PUBLIC_KEY_LEN_;
        uint8_t tmp_pubkey[X25519_PUBLIC_KEY_LEN_];
        uint8_t *p_tmp_pubkey = tmp_pubkey;

        EVP_PKEY_get_raw_public_key(p_pkey, p_tmp_pubkey, (size_t *)&pubkey_size);
        MEMCPY_M(p_pubkey, p_tmp_pubkey, X25519_PUBLIC_KEY_LEN_);

        DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"open pubkey pem2hex", p_pubkey, pubkey_size);

        EVP_PKEY_free(p_pkey);

        ret = SUCCESS_;
    }

    get_current_rss_monitor(DBG_NONE, (char *)"2");
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

int32_t openssl_ed_pubkey_hex2pem(char *p_pubkey_path, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_pkey;
    
    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"open pubkey hex2pem", p_pubkey, ED25519_PUBLIC_KEY_LEN_);

    p_pkey = EVP_PKEY_new_raw_public_key(NID_ED25519, NULL, p_pubkey, ED25519_PUBLIC_KEY_LEN_);
    if (!p_pkey)
    {
        DBG_PRINT(DBG_CLI, DBG_ERROR, (void *)"ERROR : p_pkey\n"); 
        get_current_rss_monitor(DBG_NONE, (char *)"2");
        return (ret);
    }

    do
    {
        FILE *fp;
        // ED Public Key
        fp = fopen(p_pubkey_path, "w");
        if (fp)
        {
            BIO *p_outbio = NULL;
            p_outbio = BIO_new_fp(fp, BIO_NOCLOSE);
            
            if (p_outbio)
            {
                if(!PEM_write_bio_PUBKEY(p_outbio, p_pkey))
                {
                    DBG_PRINT(DBG_CLI, DBG_ERROR, (void *)"Error writing public key data in PEM format\n");
                    break;
                }
        
                ret = SUCCESS_;
                
                BIO_free(p_outbio);
            }
            
            fclose(fp);
        }

    } while (0);

    EVP_PKEY_free(p_pkey);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
#elif (OPENSSL_102 == ENABLED)
    //
#endif // OPENSSL_111

    return (ret);
}

int32_t openssl_ed25519_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
    uint8_t data_hash[HASH_SIZE];
    
    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    openssl_sha256(data_hash, p_data, data_len);
    
#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_ed25519_verify(data_hash, HASH_SIZE, p_sig_hex, p_pubkey);
#elif (OPENSSL_102 == ENABLED)
    ret = ED25519_verify(data_hash, HASH_SIZE, p_sig_hex->sig, p_pubkey);
    if(ret)
    {
        ret = SUCCESS_;
        DBG_PRINT (DBG_CLI, DBG_INFO, (void *)"ED25519_verify, valid signature\r\n");
    }
#endif // OPENSSL_111

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (ret);
}

int32_t openssl_ed25519_verify_pubkey_path(char *p_pubkey_path, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex) 
{
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");
    
#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_pkey;

    p_pkey = EVP_PKEY_new_read_PUBKEY(p_pubkey_path);
    if (p_pkey)
    {
        int32_t pubkey_size = X25519_PUBLIC_KEY_LEN_;
        uint8_t tmp_pubkey[X25519_PUBLIC_KEY_LEN_];
        uint8_t *p_tmp_pubkey = tmp_pubkey;

        EVP_PKEY_get_raw_public_key(p_pkey, p_tmp_pubkey, (size_t *)&pubkey_size);
        DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"open pubkey pem2hex", p_tmp_pubkey, pubkey_size);

        EVP_PKEY_free(p_pkey);
        
        ret = openssl_ed25519_verify(p_data, data_len, p_sig_hex, p_tmp_pubkey);
    }
#elif (OPENSSL_102 == ENABLED)
    uint32_t pubkey_len;
    uint8_t *p_pubkey;

    p_pubkey = (uint8_t *)util_hex_file_rb(p_pubkey_path, &pubkey_len);

    if (p_pubkey == NULL)
    {
        return (ret);
    }

    if (pubkey_len != ED25519_PUBLIC_KEY_LEN_)
    {
        return (ret);
    }

    ret = openssl_ed25519_verify(p_data, data_len, p_sig_hex, p_pubkey);

    FREE_M(p_pubkey);
#endif // OPENSSL_111

    get_current_rss_monitor(DBG_INFO, (char *)"2");

    return (ret);
}

int32_t openssl_ed25519_sig(bool b_enc, char *p_prikey_path, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex) 
{
    uint32_t ret = ERROR_;
    
#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_ed25519_sign(b_enc, p_prikey_path, p_data, data_len, p_sig_hex);
#elif (OPENSSL_102 == ENABLED)
    uint32_t prikey_len;
    uint8_t *p_prikey;

    p_prikey = (uint8_t *)util_hex_file_rb(p_prikey_path, &prikey_len);

    if (p_prikey == NULL)
    {
        return (ret);
    }

    if (prikey_len != ED25519_PRIVATE_KEY_LEN_)
    {
        return (ret);
    }

    do
    {
        uint8_t data_hash[HASH_SIZE];
        
        openssl_sha256(data_hash, p_data, data_len);
        
        ED25519_sign(p_sig_hex->sig, data_hash, HASH_SIZE, p_prikey);
        
        DBG_DUMP(DBG_SEC, DBG_INFO, (void *) "ED25519_Signature", p_sig_hex->sig, ED25519_SIGNATURE_LEN_);

        openssl_ed25519_verify(p_data, data_len, p_sig_hex, &p_prikey[ED25519_PUBKEY_OFFSET]);
    } while (0);

    FREE_M(p_prikey);

    ret = SUCCESS_;
#endif // OPENSSL_111
    
    return (ret);
}

int32_t openssl_ed25519_keygen(char *p_path)
{
    int32_t ret = ERROR_;
    
#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_25519_keygen(p_path, EVP_PKEY_ED25519);
#elif (OPENSSL_102 == ENABLED)
    uint8_t pubkey[ED25519_PUBLIC_KEY_LEN_], prikey[ED25519_PRIVATE_KEY_LEN_];

    ED25519_keypair(pubkey, prikey);

    DBG_DUMP(DBG_SEC, DBG_INFO, (void *) "ED25519_prvkey", prikey, ED25519_PRIVATE_KEY_LEN_);
    DBG_DUMP(DBG_SEC, DBG_INFO, (void *) "ED25519_pubkey", pubkey, ED25519_PUBLIC_KEY_LEN_);

    if (p_path)
    {
        char pubkey_dir[SSL_PATH_SIZE];
        char prikey_dir[SSL_PATH_SIZE];
        
        sprintf(pubkey_dir, "%s%s", p_path, (char *)"ed_pubkey.hex");
        sprintf(prikey_dir, "%s%s", p_path, (char *)"ed_privkey.hex");
        
        util_hex_file_wb(pubkey_dir, pubkey, ED25519_PUBLIC_KEY_LEN_);
        util_hex_file_wb(prikey_dir, prikey, ED25519_PRIVATE_KEY_LEN_);

        ret = SUCCESS_;
    }
#endif // OPENSSL_111

    return (ret);
}

#if (ED25519_TEST == ENABLED)
int32_t openssl_ed25519_test(void)
{
    uint8_t pubkey[ED25519_PUBLIC_KEY_LEN_], prikey[ED25519_PRIVATE_KEY_LEN_];
    int32_t ret = ERROR_;
    
#if (OPENSSL_111 == ENABLED)
    //
#elif (OPENSSL_102 == ENABLED)
    uint8_t sig[ED25519_SIGNATURE_LEN_];
    uint32_t message_len = 32;
    uint8_t message[32] = {0x96, 0xC0, 0x56, 0x19, 0xD5, 0x6C, 0x32, 0x8A, 
                           0xB9, 0x5F, 0xE8, 0x4B, 0x18, 0x26, 0x4B, 0x08, 
                           0x72, 0x5B, 0x85, 0xE3, 0x3F, 0xD3, 0x4F, 0x08,
                           0x72, 0x5B, 0x85, 0xE3, 0x3F, 0xD3, 0x4F, 0x08};

    ED25519_keypair(pubkey, prikey);
#endif // OPENSSL_111

    DBG_DUMP(DBG_SEC, DBG_INFO, (void *) "ED25519_prvkey", prikey, ED25519_PRIVATE_KEY_LEN_);
    DBG_DUMP(DBG_SEC, DBG_INFO, (void *) "ED25519_pubkey", pubkey, ED25519_PUBLIC_KEY_LEN_);

#if (OPENSSL_111 == ENABLED)
        //
#elif (OPENSSL_102 == ENABLED)
    ED25519_sign(sig, message, message_len, prikey);
    DBG_DUMP(DBG_SEC, DBG_INFO, (void *) "ED25519_sig", sig, ED25519_SIGNATURE_LEN_);
    
    ret = ED25519_verify(message, message_len, sig, pubkey);
#endif // OPENSSL_111

    if(ret)
    {
        DBG_PRINT(DBG_CLI, DBG_INFO, (void *)"ED25519_verify, valid signature\r\n");
    }

    return (SUCCESS_);
}
#endif // ED25519_TEST


