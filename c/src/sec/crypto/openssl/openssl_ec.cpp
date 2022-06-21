/**
    @file openssl_ec.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

int32_t g_ec_algo = NID_X9_62_prime256v1;

EC_KEY *EC_KEY_new_raw_PUBKEY(uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
    EC_KEY *eckey = NULL;

    do
    {
        eckey = EC_KEY_new();
        if (!eckey) break;
        
        do
        {
            EC_GROUP *ecgroup;

            ecgroup = EC_GROUP_new_by_curve_name(g_ec_algo);
            if (!ecgroup) break;

            EC_KEY_set_group(eckey, ecgroup);
            EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

            do
            {
                EC_POINT *pubkey;

                pubkey = EC_POINT_new(ecgroup);
                if (!pubkey) break;

                do
                {
                    char pubkey_str[UNCOMP_PUBKEY_STR_SIZE];
                    
                    if (p_pubkey[0] == PUBKEY_DELIMITER_EC_UNCOMP)
                    {
                        ret = util_hex2str_temp(p_pubkey, UNCOMP_PUBKEY_SIZE, pubkey_str, UNCOMP_PUBKEY_STR_SIZE, false);
                    
                        DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"uncomp_pubkey", p_pubkey, UNCOMP_PUBKEY_SIZE);
                        DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"uncomp_pubkey_str(%s)\n",  pubkey_str);
                    }
                    else
                    {
                        ret = util_hex2str_temp(p_pubkey, COMP_PUBKEY_SIZE, pubkey_str, COMP_PUBKEY_STR_SIZE, false);
                    
                        DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"comp_pubkey", p_pubkey, COMP_PUBKEY_SIZE);
                        DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"comp_pubkey_str(%s)\n",  pubkey_str);
                    }

                    if (ret == SUCCESS_)
                    {
                        EC_POINT_hex2point(ecgroup, (const char*)pubkey_str, pubkey, NULL);
                        EC_KEY_set_public_key(eckey, pubkey);
                    }
                } while(0);

                EC_POINT_free(pubkey);
            } while(0);

            EC_GROUP_free(ecgroup);
        } while(0);

        if (ret != SUCCESS_)
        {
            EC_KEY_free(eckey);

            eckey = NULL;
        }
    } while(0);

    return (eckey);
}

ECDSA_SIG *ECDSA_SIG_new_raw_SIG(SSL_SIG_U *p_sig_hex)
{
    int32_t ret = ERROR_;
    ECDSA_SIG *sig;
    
    do
    {
        sig = ECDSA_SIG_new();
        
        if(!sig) break;
        
        do
        {
            char sig_r_str[SIG_R_STR_SIZE];
            char sig_s_str[SIG_S_STR_SIZE];

            util_hex2str_temp(p_sig_hex->ec.r, SIG_R_SIZE, sig_r_str, SIG_R_STR_SIZE, false);
            util_hex2str_temp(p_sig_hex->ec.s, SIG_S_SIZE, sig_s_str, SIG_S_STR_SIZE, false);

            do
            {
#if (OPENSSL_111 == ENABLED)
                BIGNUM *r_bn = BN_new();
                BIGNUM *s_bn = BN_new();

                ASSERT_M (r_bn && s_bn);
                
                BN_hex2bn(&r_bn, sig_r_str);
                BN_hex2bn(&s_bn, sig_s_str);
                
                ECDSA_SIG_set0(sig, r_bn, s_bn);
#elif (OPENSSL_102 == ENABLED)
                BN_hex2bn(&sig->r, sig_r_str);
                BN_hex2bn(&sig->s, sig_s_str);
#endif // OPENSSL_111

                ret = SUCCESS_;
            } while (0);
        } while(0);

        if (ret != SUCCESS_)
        {
            ECDSA_SIG_free(sig);

            sig = NULL;
        }
    } while(0);

    return (sig);
}

int32_t raw_SIG_new_ECDSA_SIG(ECDSA_SIG *sig, SSL_SIG_U *p_sig_hex)
{
    int32_t ret = ERROR_;
    
    do
    {
        char *hexR, *hexS;
        /*print R & S value in hex format */
#if (OPENSSL_111 == ENABLED)
        const BIGNUM *r_bn = ECDSA_SIG_get0_r(sig);
        const BIGNUM *r_sn = ECDSA_SIG_get0_s(sig);

        if (!r_bn || !r_sn)
        {
            break;
        }
        
        hexR = BN_bn2hex_z(r_bn);
        hexS = BN_bn2hex_z(r_sn);
#elif (OPENSSL_102 == ENABLED)
        hexR = BN_bn2hex_z(sig->r);
        hexS = BN_bn2hex_z(sig->s);
#endif // OPENSSL_111
        if(!hexR) break;
        if(!hexS)
        {
            OPENSSL_free(hexR);
            break;
        }
        
        DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"hexR(%d) hexS(%d)\n", STRLEN_M(hexR), STRLEN_M(hexS));
        DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"R: %s \n    S: %s\n", hexR, hexS);

        ASSERT_M(STRLEN_M(hexR) == (SIG_R_SIZE*2));
        ASSERT_M(STRLEN_M(hexS) == (SIG_S_SIZE*2));

        do
        {
            int32_t len;
            
            // String to Hex
            len = SIG_R_SIZE;
            util_str2hex(hexR, p_sig_hex->ec.r, &len);
            len = SIG_S_SIZE;
            util_str2hex(hexS, p_sig_hex->ec.s, &len);

            ret = SUCCESS_;
        } while(0);

        OPENSSL_free(hexR);
        OPENSSL_free(hexS);
    } while(0);

    return (ret);
}

int32_t ECDSA_new_do_verify(uint8_t *p_data, uint32_t data_len, ECDSA_SIG *p_sig, EC_KEY *p_eckey)
{
    int32_t ret = ERROR_, ssl_ret;
    
    ssl_ret = ECDSA_do_verify(p_data, data_len, p_sig, p_eckey);
    
    if(ssl_ret == SSL_VERIFY_SUCCESS) 
    {
        DBG_PRINT(DBG_SEC, DBG_INFO, (void *) "verified SSL_VERIFY_SUCCESS\n");
        ret = SUCCESS_;
    }
    else if(ssl_ret == SSL_VERIFY_INCORRECT)
    {
        DBG_PRINT(DBG_SEC, DBG_INFO, (void *) "verified SSL_VERIFY_INCORRECT\n");
    }
    else if(ssl_ret == SSL_VERIFY_ERROR)
    {
        DBG_PRINT(DBG_SEC, DBG_INFO, (void *) "verified SSL_VERIFY_ERROR\n"); 
    }

    return (ret);
}

void EC_KEY_print(EC_KEY *eckey)
{
    const BIGNUM *d = EC_KEY_get0_private_key(eckey);
    const EC_POINT *Q = EC_KEY_get0_public_key(eckey);
    const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    char *p_d, *p_x, *p_y;
    
    if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, Q, x, y, NULL)) return;
    
    p_d = BN_bn2hex_z(d);
    p_x = BN_bn2hex_z(x);
    p_y = BN_bn2hex_z(y);
    DBG_PRINT(DBG_SEC, DBG_INFO, (void *) "private key : (%s)\n", p_d);
    DBG_PRINT(DBG_SEC, DBG_INFO, (void *) "public key : (04%s%s)\n", p_x, p_y);
    // ~Print
    
    BN_free(x);
    BN_free(y);
    
    OPENSSL_free(p_d);
    OPENSSL_free(p_x);
    OPENSSL_free(p_y);
}

int32_t openssl_ec_pubkey_hex2pem(char *p_pubkey_path, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
    EC_KEY *eckey;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

    ASSERT_M(p_pubkey_path);
    ASSERT_M(p_pubkey);
    
    do
    {
        eckey = EC_KEY_new_raw_PUBKEY(p_pubkey);
        if (!eckey) break;

        do
        {
            EVP_PKEY *pkey;
            
            pkey = EVP_PKEY_new();
            if (!pkey) break;

            do
            {
                EVP_PKEY_set1_EC_KEY(pkey, eckey);
                
                ret = PEM_new_write_PUBKEY(p_pubkey_path, pkey);
            } while(0);

            EC_KEY_free(eckey);
        } while(0);

        EC_KEY_free(eckey);
    } while (0);
    
    get_current_rss_monitor(DBG_INFO, (char *)"2");
    
    return (ret);
}

int32_t openssl_ec_pubkey_pem2hex(char *p_pubkey_path, uint8_t *p_pubkey)
{
    int32_t ret = ERROR_;
    
    EVP_PKEY *pubkey_in = NULL;
    EC_KEY *pubKey;
    EC_GROUP *ecgroup;
    EC_POINT *pub;
    char *comp_pubkey_str;
    FILE* fp_in;    

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

    fp_in = fopen (p_pubkey_path, "r");
    if (!fp_in) return (ret);

    do
    {
        pubkey_in = PEM_read_PUBKEY(fp_in, NULL, NULL, NULL);
        
        if(!pubkey_in) break;

        do 
        {
            pubKey = EVP_PKEY_get1_EC_KEY(pubkey_in);
            if (!pubKey) break;

            do
            {
                ecgroup = EC_GROUP_new_by_curve_name(g_ec_algo);
                if (!ecgroup) break;

                do
                {
                    pub = (EC_POINT *)EC_KEY_get0_public_key((const EC_KEY*)pubKey);
                    if (!pub) break;

                    do
                    {

                        comp_pubkey_str = EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_COMPRESSED, NULL);
                        if (!comp_pubkey_str) break;

                        DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"my_comp_pubkey : (%s)\n", comp_pubkey_str);
                        
                        util_str2hex_temp(comp_pubkey_str, p_pubkey, COMP_PUBKEY_SIZE, false);
                        OPENSSL_free(comp_pubkey_str);

                        ret = SUCCESS_;
                        
                    }while(0);

                    //EC_POINT_free(pub);
                }while(0);
               
                EC_GROUP_free(ecgroup);
            }while(0);

            EC_KEY_free(pubKey);
        } while(0);

        EVP_PKEY_free(pubkey_in);
    }while(0);

    fclose (fp_in);

    get_current_rss_monitor(DBG_INFO, (char *)"2");
    
    return (ret);
}

int32_t openssl_ec_key_gen(char *p_path)
{
    EC_KEY* eckey = NULL;
    EVP_PKEY* pkey = NULL;
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

    // These function calls initialize openssl for correct work.  
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    do
    {
        // Create a EC key sructure, setting the group type from NID
        eckey = EC_KEY_new_by_curve_name(g_ec_algo);
        if(!eckey) return ret;

        do

        {
            // For cert signing, we use the OPENSSL_EC_NAMED_CURVE flag
            EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

            // Create the public/private EC key pair here
            if (!EC_KEY_generate_key(eckey))
            {
                break;
            }

            EC_KEY_print(eckey);

            // Converting the EC key into a PKEY structure let us
            // handle the key just like any other key pair./
            pkey = EVP_PKEY_new();
            if(!pkey) break;

            do
            {
                if (!EVP_PKEY_assign_EC_KEY(pkey,eckey)) break;

                // Now we show how to extract EC-specifics from the key
                eckey = EVP_PKEY_get1_EC_KEY(pkey);

                EVP_PKEY_set1_EC_KEY(pkey, eckey);

                if (p_path)
                {
                    char pubkey_dir[SSL_PATH_SIZE];
                    char prikey_dir[SSL_PATH_SIZE];
                    
                    sprintf(pubkey_dir, "%s%s", p_path, (char *)"pubkey.pem");
                    sprintf(prikey_dir, "%s%s", p_path, (char *)"privkey.pem");

                    // ED Private Key
                    PEM_new_write_PRIKEY(prikey_dir, pkey);
                    
                    // ED Public Key
                    PEM_new_write_PUBKEY(pubkey_dir, pkey);
                }
                else
                {
                    PEM_new_write_PUBKEY((char *)"pubkey.pem", pkey);
                    PEM_new_write_PRIKEY((char *)"privkey.pem", pkey);
                }

                ret = SUCCESS_;
            } while(0);
            EVP_PKEY_free(pkey);
        } while(0);
        
        EC_KEY_free(eckey);
    }while(0);

    get_current_rss_monitor(DBG_INFO, (char *)"2");
    
    return (ret);
}

int32_t openssl_ec_pubkey_gen(char *pri_key) 
{
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    if(!pri_key) return ret;
    do
    {
        EC_KEY* eckey = EC_KEY_new();
        if(!eckey) break;

        do
        {
            EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(g_ec_algo);
            if(!ecgroup) break;

            do
            {
                EC_KEY_set_group(eckey, ecgroup);
                EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

                /* pri key */
                BIGNUM* prv = BN_new();
                if(!prv) break;

                BN_hex2bn(&prv, pri_key);
                DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"Private key: %s \n", pri_key);

                do
                {
                    EC_POINT* pub = EC_POINT_new(ecgroup);
                    if(!pub) break;
                    
                    do
                    {
                        /* pub key */
                        EC_POINT_mul(ecgroup, pub, prv, NULL, NULL, NULL);

                        /* add the private & public key to the EC_KEY structure */
                        EC_KEY_set_private_key(eckey, prv);
                        EC_KEY_set_public_key(eckey, pub);

                        char* hexPKey;

                        hexPKey = EC_POINT_point2hex(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, NULL);
                        if(!hexPKey) break;

                        do
                        {
                            //EC_POINT_hex2point(ecgroup, hexPKey, POINT_CONVERSION_UNCOMPRESSED, BN_CTX *)
                            /* create hash */

                            EVP_PKEY* pkey = EVP_PKEY_new();
                            DBG_PRINT(DBG_SEC, DBG_INFO, (void *)"Public key:  %s \n", hexPKey);
                            if(!pkey) break;

                            do
                            {
                                EVP_PKEY_set1_EC_KEY(pkey, eckey);

                                PEM_new_write_PUBKEY((char *)"pubkey.pem", pkey);
                                PEM_new_write_PRIKEY((char *)"privkey.pem", pkey);

                                ret = SUCCESS_;
                            }while(0);
                            
                            EVP_PKEY_free(pkey);
                        }while(0);
                        
                        OPENSSL_free(hexPKey);
                        
                    }while(0);
                    EC_POINT_free(pub);
                        
                }while(0);
                BN_free(prv);
                
            }while(0);
            EC_GROUP_free(ecgroup);
            
        } while(0);
        EC_KEY_free(eckey);        
        
    }while(0);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (ret);
}

int32_t openssl_ec_pubkey_decompress(char *p_comp_pubkey, char *p_uncomp_pubkey)
{
    int32_t ret = ERROR_;
    EC_KEY *eckey;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

    eckey = EC_KEY_new();
    if(!eckey) return ret;

    do
    {
        EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(g_ec_algo);
        if(!ecgroup) break;
        
        EC_KEY_set_group(eckey, ecgroup);
        EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
        
        DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"Compressed PubKey:  %s \n", p_comp_pubkey);

        do
        {
            
            EC_POINT* pubkey = EC_POINT_new(ecgroup);
            if(!pubkey) break;

            EC_POINT_hex2point(ecgroup, (const char*)p_comp_pubkey, pubkey, NULL);

            do
            {
                char *uncomp_pubkey_str;

                uncomp_pubkey_str = EC_POINT_point2hex(ecgroup, pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL);
                if(!uncomp_pubkey_str) break;
                
                STRCPY_M(p_uncomp_pubkey, uncomp_pubkey_str);
                
                DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"Uncompressed PubKey:  %s \n", p_uncomp_pubkey);

                OPENSSL_free(uncomp_pubkey_str);
                
                ret = SUCCESS_;
            }while(0);
            
            EC_POINT_free(pubkey);
            
        }while(0);
        EC_GROUP_free(ecgroup);
        
    }while(0);
    EC_KEY_free(eckey);

    get_current_rss_monitor(DBG_INFO, (char *)"2");
    
    return (ret);
}

int32_t openssl_ec_pubkey_compress(char *p_uncomp_pubkey, char *p_comp_pubkey)
{ // temporary
    int32_t ret = ERROR_;
    
    EC_KEY *eckey;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

    eckey = EC_KEY_new();
    if(!eckey) return ret;

    do
    {
        EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(g_ec_algo);
        if(!ecgroup) break;
        
        EC_KEY_set_group(eckey, ecgroup);
        EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

        DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"Uncompressed PubKey:  %s \n", p_uncomp_pubkey);

        do 
        {
            EC_POINT* pubkey = EC_POINT_new(ecgroup);
            if(!pubkey) break;
            EC_POINT_hex2point(ecgroup, (const char*)p_uncomp_pubkey, pubkey, NULL);

            do
            {
                char *comp_pubkey_str;
                
                comp_pubkey_str = EC_POINT_point2hex(ecgroup, pubkey, POINT_CONVERSION_COMPRESSED, NULL);
                if(!comp_pubkey_str) break;
                
                STRCPY_M(p_comp_pubkey, comp_pubkey_str);

                DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"Compressed PubKey:  %s \n", p_comp_pubkey);

                OPENSSL_free(comp_pubkey_str);

                ret = SUCCESS_;
            }while(0);
            EC_POINT_free(pubkey);
            
        }while(0);
        EC_GROUP_free(ecgroup);
        
    }while(0);
    EC_KEY_free(eckey);

    get_current_rss_monitor(DBG_INFO, (char *)"2");
    
    return (ret);
}

