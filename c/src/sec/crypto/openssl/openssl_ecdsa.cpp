/**
    @file openssl_ecdsa.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

int32_t openssl_ecdsa_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_comp_pubkey)
{
    int32_t ret = ERROR_;
    uint8_t data_hash[HASH_SIZE];

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

    openssl_sha256(data_hash, p_data, data_len);
    
    do
    {
        ECDSA_SIG *sig;
        
        sig = ECDSA_SIG_new_raw_SIG(p_sig_hex);
        if(!sig) break;

        do
        {
            EC_KEY *eckey;

            eckey = EC_KEY_new_raw_PUBKEY(p_comp_pubkey);
            if (!eckey) break;

            do
            {
                ret = ECDSA_new_do_verify(data_hash, HASH_SIZE, sig, eckey);
            } while(0);

            EC_KEY_free(eckey);
        } while(0);
        

        ECDSA_SIG_free(sig);
    } while(0);

    get_current_rss_monitor(DBG_INFO, (char *)"2");

    return (ret);
}

int32_t openssl_ecdsa_verify2(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, EC_KEY *eckey)
{
    int32_t ret = ERROR_;
    uint8_t data_hash[HASH_SIZE];

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

    openssl_sha256(data_hash, p_data, data_len);

    do
    {
        ECDSA_SIG *sig;
        
        sig = ECDSA_SIG_new_raw_SIG(p_sig_hex);

        if(!sig) break;

        do
        {
            ret = ECDSA_new_do_verify(data_hash, HASH_SIZE, sig, eckey);
        } while(0);

        ECDSA_SIG_free(sig);
    } while(0);

    get_current_rss_monitor(DBG_INFO, (char *)"2");

    return ret;
}


int32_t openssl_ecdsa_verify_pubkey_path(char *p_pubkey_path, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex) 
{
    int32_t ret = ERROR_;
    EVP_PKEY *pubkey_in = NULL;
    FILE* fp_in;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    fp_in = fopen (p_pubkey_path, "r");
    if (!fp_in) return (ret);

    pubkey_in = PEM_read_PUBKEY(fp_in, NULL, NULL, NULL);
    fclose (fp_in);

    if(!pubkey_in) return (ret);

    do
    {
        EC_KEY* pubKey = EVP_PKEY_get1_EC_KEY(pubkey_in);
        if(!pubKey) break;

        do
        {
#if 0
            const EC_POINT *pub;

            pub = EC_KEY_get0_public_key(pubKey);
            if(!pub) break;

            do
            {
                EC_GROUP* ecgroup;
                
                ecgroup = EC_GROUP_new_by_curve_name(g_ec_algo);
                if(!ecgroup) break;

                do
                {
                    char *hex_pubkey_str;
                    uint8_t hex_pubkey[COMP_PUBKEY_SIZE];
                    
                    hex_pubkey_str = EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_COMPRESSED, NULL);
                    if(!hex_pubkey_str) break;

                    do
                    {
                        util_str2hex_temp(hex_pubkey_str, hex_pubkey, COMP_PUBKEY_SIZE, false);

                        DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"hex_pubkey", hex_pubkey, COMP_PUBKEY_SIZE);

                        ret = openssl_ecdsa_verify(p_data, HASH_SIZE, p_sig_hex, hex_pubkey);

                        DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"ecdsa verify ret(%d)\n",  ret);
                    } while(0);

                    FREE_M(hex_pubkey_str);
                    
                } while(0);
                
                EC_GROUP_free(ecgroup);
            } while(0);

//            EC_POINT_free((EC_POINT *)pub);
#else
            ret = openssl_ecdsa_verify2(p_data, HASH_SIZE, p_sig_hex, pubKey);

            DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"ecdsa verify ret(%d)\n",  ret);
#endif
        }while(0);    

        EC_KEY_free(pubKey);
    }while(0);

    EVP_PKEY_free(pubkey_in);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return ret;
}

int32_t openssl_ecdsa_sig(bool b_enc, char *p_prikey_path, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex) 
{
    /* Read private key */
    int32_t ret = ERROR_;
    
    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    do
    {
        EVP_PKEY *prikey_in = NULL;
        
        prikey_in = EVP_PKEY_new_read_PRIKEY(b_enc, p_prikey_path);
        if (!prikey_in) break;
        
        do
        {
            uint8_t hash[HASH_SIZE];
            
            EC_KEY* eckey_in = EVP_PKEY_get1_EC_KEY(prikey_in);
            if(!eckey_in) break;

            DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"Data : ", p_data, data_len);    
            
            // Data Hash
            openssl_sha256(hash, p_data, data_len);

            DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"Hash : ", hash, HASH_SIZE);

            do
            {
                // Create and verify signature
                ECDSA_SIG *sig = ECDSA_do_sign(hash, HASH_SIZE, eckey_in);
                if(!sig) break;
                
                do 
                {
                    // Verify signature with Private Key
                    ret = ECDSA_new_do_verify(hash, HASH_SIZE, sig, eckey_in);

                    if (ret == SUCCESS_)
                    {
                        ret = raw_SIG_new_ECDSA_SIG(sig, p_sig_hex);
                    }
                }while(0);
                
                ECDSA_SIG_free(sig);
                
            }while(0);

            EC_KEY_free(eckey_in);
        }while(0);
        
        EVP_PKEY_free(prikey_in);
    }while(0);
    
    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (ret);
}

