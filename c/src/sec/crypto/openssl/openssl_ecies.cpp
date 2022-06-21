/**
    @file openssl_ecies.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#if (ECIES_TEST == ENABLED)
const char g_ecies_privkey[] = \
"-----BEGIN PRIVATE KEY-----\n" \
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguXuf4bSOJ4x4O566\n" \
"/N4/A1dYPm09YF46FKpRpnostnqhRANCAARhtwt8gpWx5MN14ZjtjMJswpjCPR/J\n" \
"PfjCgojGuJ35NUoov/ENRsw7CtGmUpfN1rpGI25ztatqJLtoNLAlfBWZ\n" \
"-----END PRIVATE KEY-----\n";

const char g_ecies_pubkey[] = \
"-----BEGIN PUBLIC KEY-----\n" \
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYbcLfIKVseTDdeGY7YzCbMKYwj0f\n" \
"yT34woKIxrid+TVKKL/xDUbMOwrRplKXzda6RiNuc7WraiS7aDSwJXwVmQ==\n" \
"-----END PUBLIC KEY-----\n";

#endif // ECIES_TEST

EC_POINT *EC_POINT_mult_BN(const EC_GROUP *group, EC_POINT *P, const EC_POINT *a, const BIGNUM *b, BN_CTX *ctx)
{
    if (P == NULL) P = EC_POINT_new(group);

    for(int i = BN_num_bits(b); i >= 0; i--) {
        EC_POINT_dbl(group, P, P, ctx);
        
        if (BN_is_bit_set(b, i))
        {
            EC_POINT_add(group, P, P, a, ctx);
        }
        else
        {
            const EC_POINT *O = EC_POINT_new(group);
            EC_POINT_add(group, P, P, O, ctx);
            EC_POINT_free((EC_POINT *)O);
        }
    }

    return P;
}

int EC_KEY_public_derive_S(const EC_KEY *pubkey, point_conversion_form_t fmt, BIGNUM *S, BIGNUM *R)
{
    int ret=ERROR_;
    BIGNUM *n, *r, *Py;

    DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    BN_CTX *ctx = BN_CTX_new();
    if(!ctx) return ret;

    do 
    {
        const EC_GROUP *group = EC_KEY_get0_group(pubkey);
        if(!group) break;          
        const EC_POINT *Kb = EC_KEY_get0_public_key(pubkey);
        if(!Kb) break;
        
        n = BN_new();
        if(!n) break;

        do
        {
            r = BN_new();
            if(!r) break;

            do
            {
                Py = BN_new();
                if(!Py) break;

                do
                {
                    int bits;
                    
                    const EC_POINT *G = EC_GROUP_get0_generator(group);
                    if(!G) break;

                    EC_GROUP_get_order(group, n, ctx);
                    bits = BN_num_bits(n);
                    BN_rand(r, bits, -1, 0);

                    /* calculate R = rG */
                    EC_POINT *Rp = EC_POINT_mult_BN(group, NULL, G, r, ctx);
                    if(!Rp) break;

                    do
                    {
                        /* calculate S = Px, P = (Px,Py) = Kb R */
                        EC_POINT *P = EC_POINT_mult_BN(group, NULL, Kb, r, ctx);
                        if(!P) break;

                        do
                        {
                            if (!EC_POINT_is_at_infinity(group, P)) 
                            {
                                EC_POINT_get_affine_coordinates_GF2m(group, P, S, Py, ctx);
                                EC_POINT_point2bn(group, Rp, fmt, R, ctx);
                                ret = SUCCESS_;
                            }
                        } while(0);

                        EC_POINT_free(P);
                    } while (0);
                    
                    EC_POINT_free(Rp);
                }while(0);

                BN_free(Py);
            }while(0);

            BN_free(r);
        }while(0);

        BN_free(n);
    }while(0);

    BN_CTX_free(ctx);
    
    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return ret;
}

int EC_KEY_private_derive_S(const EC_KEY *prikey, const BIGNUM *R, BIGNUM *S)
{
    int ret = ERROR_;
    BN_CTX *ctx;
    BIGNUM *n, *Py;
    EC_POINT *Rp, *P;

    DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    ctx = BN_CTX_new();
    if(!ctx) return ret;

    do
    {
        n = BN_new();
        if(!n) break;

        do
        {
            Py = BN_new();
            if(!Py) break;

            do
            {
                const EC_GROUP *group = EC_KEY_get0_group(prikey);
                if(!group) break;
                
                Rp = EC_POINT_bn2point(group, R, NULL, ctx);
                if(!Rp) break;

                do
                {
                    const BIGNUM *kB = EC_KEY_get0_private_key(prikey);
                    if(!kB) break;
                    
                    EC_GROUP_get_order(group, n, ctx);
                    /* Calculate S = Px, P = (Px, Py) = R kB */
                    P = EC_POINT_mult_BN(group, NULL, Rp, kB, ctx);
                    if(!P) break;
                    if (!EC_POINT_is_at_infinity(group, P)) {
                        EC_POINT_get_affine_coordinates_GF2m(group, P, S, Py, ctx);
                        ret = SUCCESS_;
                    }
                    EC_POINT_free(P);
                    
                }while(0); 
                EC_POINT_free(Rp);
                
            }while(0);
            BN_free(Py);
                
        }while(0);
        BN_free(n);
            
    }while(0);

    BN_CTX_free(ctx);

    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return ret;
}

// IEEE1363 ECIES encryption.
int32_t openssl_ecies_encrypt(const EC_KEY *p_pubkey, const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_plaintext, uint32_t plaintext_len, uint8_t *p_enc_msg, uint32_t *p_enc_msg_len)
{
    int32_t ret = ERROR_;
    BIGNUM *R;

    DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");   
    
    R = BN_new();
    if(!R) return ret;

    do
    {
        BIGNUM *S = BN_new();
        if(!S) break;

        do
        {
            /* make sure it's not at infinity */
            while(EC_KEY_public_derive_S(p_pubkey, POINT_CONVERSION_COMPRESSED, S, R) != 0);

            const EVP_MD *md = EVP_sha256();

            uint32_t cnt;
            uint32_t key_len_byte = OPENSSL_SYM_KEY_LEN;
            uint8_t key[key_len_byte*2], key_1[key_len_byte], key_2[key_len_byte];
            uint8_t *p_R_out, *p_S_out, mac_out[OPENSSL_ECIES_MAC_LEN];
            uint32_t R_len, S_len;

            R_len = BN_num_bytes(R);
            S_len = BN_num_bytes(S);

            //DBG_PRINT(DBG_SEC, DBG_INFO, (void *)"R_len(%d) S_len(%d)\n", R_len, S_len);

            /* then reverse operation */
            if(R_len != OPENSSL_ECIES_R_LEN)
            {
                DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"R_size invalid(%d)\n", R_len); //error
                break;
            }

            uint8_t password[S_len], R_out[R_len];

            p_R_out = R_out;
            p_S_out = password;
            
            BN_bn2bin(R, p_R_out);
            BN_bn2bin(S, p_S_out);

            DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "R_out", (uint8_t *)p_R_out, R_len);
            DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "S_out", (uint8_t *)p_S_out, S_len);

            openssl_kdf2(md, password, S_len, p_p1, p1_len, 2*key_len_byte, key);
            DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "kdf_key", (uint8_t *)key, 2*key_len_byte);

            for (cnt=0; cnt<key_len_byte; cnt++)
            {
                key_1[cnt] = key[cnt];
                key_2[cnt] = key[OPENSSL_SYM_KEY_LEN+cnt];
            }
/////////////
            /* init vector */
            unsigned char iv[AES_BLOCK_SIZE];
            MEMSET_M(iv, 0x00, AES_BLOCK_SIZE);

            /* Encrypt the plaintext */
            *p_enc_msg_len = openssl_aes_cbc_encrypt (p_plaintext, plaintext_len, key_1, iv, p_enc_msg);
            DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "aes_enc", (uint8_t *)p_enc_msg, *p_enc_msg_len);
////////////

            if (!*p_enc_msg_len)
            {
                break;
            }
            
            unsigned int len, input_len;

            /* calculate MAC */
            input_len = *p_enc_msg_len;
            if(p2_len)
            {
                uint32_t p2_len_tmp = p2_len;

                MEMCPY_M(&p_enc_msg[input_len], p_p2, p2_len);
                input_len += p2_len;
                
                for(cnt=OPENSSL_ECIES_P2_LEN; cnt>0; cnt--)
                {
                    p_enc_msg[input_len+cnt-1] = p2_len_tmp % 256;
                    p2_len_tmp /= 256;
                }

                input_len += OPENSSL_ECIES_P2_LEN;
            }
            
            HMAC(md, key_2, key_len_byte, p_enc_msg, input_len, mac_out, &len);

            if( len != OPENSSL_ECIES_MAC_LEN)
            {
                DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"mac_size invalid(%d)\n",len); //error
                break;
            }
            
            //DBG_DUMP(DBG_SEC, DBG_INFO, (void *) "ciphertext", (uint8_t *)encrypted_msg, *encrypted_msg_size);
            
            DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "mac_out", (uint8_t *)mac_out, OPENSSL_ECIES_MAC_LEN);

            DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"enc_msg_len(%d) R_len(%d) S_len(%d) MAC_len(%d)\n", *p_enc_msg_len, R_len, S_len, OPENSSL_ECIES_MAC_LEN);
            
            MEMCPY_M(p_enc_msg + *p_enc_msg_len, p_R_out, R_len);
            *p_enc_msg_len += OPENSSL_ECIES_R_LEN;
            MEMCPY_M(p_enc_msg + *p_enc_msg_len, mac_out, OPENSSL_ECIES_MAC_LEN);
            *p_enc_msg_len += OPENSSL_ECIES_MAC_LEN;

            //DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"cipher", encrypted_msg, *encrypted_msg_size);

            ret = SUCCESS_;         
        }while(0);

        BN_free(S);
    }while(0);
    
    BN_free(R);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return ret;
}

int32_t openssl_ecies_decrypt(const EC_KEY *p_prikey, const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                    const uint8_t *p_ciphertext, uint32_t ciphertext_len, const uint8_t *p_cipher_R, const uint8_t *p_cipher_mac, 
                                    uint8_t *p_plaintext, uint32_t *p_plaintext_len)
{
    int32_t ret = ERROR_;
    BIGNUM *R;

    DBG_PRINT(DBG_SEC, DBG_NONE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_NONE, (char *)"1");   

    DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "ciphertext", (uint8_t *)p_ciphertext, ciphertext_len);
    DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "R_in", (uint8_t *)p_cipher_R, OPENSSL_ECIES_R_LEN);
    DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "mac_in", (uint8_t *)p_cipher_mac, OPENSSL_ECIES_MAC_LEN);

    R = BN_bin2bn(p_cipher_R, OPENSSL_ECIES_R_LEN, BN_new());
    if(!R) return ret;
    
    do
    {
        BIGNUM *S = BN_new();
        if(!S) break;
          
        if (EC_KEY_private_derive_S(p_prikey, R, S) != 0) {
            DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"Key derivation failed\n");
            return ret;
        }

        uint32_t S_len = BN_num_bytes(S);
        uint8_t password[S_len];
        BN_bn2bin(S, password);

        do
        {
            const EVP_MD *md = EVP_sha256();
            uint32_t cnt;
            uint32_t key_len_byte = OPENSSL_SYM_KEY_LEN;
            uint8_t key[key_len_byte*2], key_1[key_len_byte], key_2[key_len_byte];
            uint8_t mac_out[OPENSSL_ECIES_MAC_LEN];

            openssl_kdf2(md, password, S_len, p_p1, p1_len, 2*key_len_byte, key);
            DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "kdf_key", (uint8_t *)key, 2*key_len_byte);

            for (cnt=0; cnt<key_len_byte; cnt++)
            {
                key_1[cnt] = key[cnt];
                key_2[cnt] = key[OPENSSL_SYM_KEY_LEN+cnt];
            }

            /* init vector */
            unsigned char iv[AES_BLOCK_SIZE];
            MEMSET_M(iv, 0x00, AES_BLOCK_SIZE);
            
            *p_plaintext_len = openssl_aes_cbc_decrypt(p_ciphertext, ciphertext_len, key_1, iv, p_plaintext);
            DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "aes_dec", (uint8_t *)p_plaintext, *p_plaintext_len);

            if (!*p_plaintext_len)
            {
                break;
            }
            
            unsigned int len, input_len;
            
            /* calculate MAC */
            if(p2_len)
            {
                uint32_t p2_len_tmp = p2_len;
                uint8_t ciphertext_tmp[ciphertext_len+p2_len+OPENSSL_ECIES_P2_LEN];

                input_len = 0;
                MEMCPY_M(&ciphertext_tmp[input_len], p_ciphertext, ciphertext_len);
                input_len += ciphertext_len;
                MEMCPY_M(&ciphertext_tmp[input_len], p_p2, p2_len);
                input_len += p2_len;
                
                for(cnt=OPENSSL_ECIES_P2_LEN; cnt>0; cnt--)
                {
                    ciphertext_tmp[input_len+cnt-1] = p2_len_tmp % 256;
                    p2_len_tmp /= 256;
                }

                input_len += OPENSSL_ECIES_P2_LEN;
            }
            HMAC(md, key_2, key_len_byte, p_ciphertext, ciphertext_len, mac_out, &len);
            DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "mac_out", (uint8_t *)mac_out, len);

            if (!MEMCMP_M((void *)mac_out, (void *)p_cipher_mac, len))
            {
                ret = SUCCESS_;
            }
            else
            {
                ASSERT_M(0);
            }
        }while(0);
        BN_free(S);
        
    }while(0);
    
    BN_free(R);

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (ret);
}

#if (ECIES_TEST == ENABLED)
int32_t openssl_ecies_test(void) 
{
    int32_t ret = ERROR_;

    get_current_rss_monitor(DBG_NONE, (char *)"1");
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    util_rand_init();

    // private Key
    BIO *pri_b = BIO_new_mem_buf((void*)g_ecies_privkey, sizeof(g_ecies_privkey));
    //EVP_PKEY *pkey;
    EC_KEY *pri_eckey = NULL;
    EVP_PKEY *pri_pkey = PEM_read_bio_PrivateKey(pri_b, NULL, NULL, NULL);
    pri_eckey = EVP_PKEY_get1_EC_KEY(pri_pkey);
    // ~private Key

    // public Key
    BIO *pub_b = BIO_new_mem_buf((void*)g_ecies_pubkey, sizeof(g_ecies_pubkey));
    //EVP_PKEY *pkey;
    EC_KEY *pub_eckey = NULL;
    EVP_PKEY *pub_pkey = PEM_read_bio_PUBKEY(pub_b, NULL, NULL, NULL);
    pub_eckey = EVP_PKEY_get1_EC_KEY(pub_pkey);
    // ~public Key

    // Encrypted
    uint8_t plaintext[2048];
    uint32_t plaintext_len;
    
    uint8_t enc_msg[2048];
    uint32_t enc_msg_size;

    uint8_t kdp[16] = { 0x75, 0xEE, 0xF8, 0x1A, 0xA3, 0x04, 0x1E, 0x33, 0xB8, 0x09, 0x71, 0x20, 0x3D, 0x2C, 0x0C, 0x52 };
    uint32_t kdp_len = 16;

#if 1
    for (plaintext_len=0; plaintext_len<112; plaintext_len++)
    {
        plaintext[plaintext_len] = plaintext_len;
    }
#else
    STRCPY_M((char *)plaintext, "super secret message super secret message");
    plaintext_len = STRLEN_M((char *)plaintext);
#endif

    DBG_DUMP(DBG_SEC, DBG_INFO, (void *)"plaintext", plaintext, plaintext_len);
    
    //openssl_ecies_encrypt_tmp(pub_eckey, plaintext, plaintext_size, enc_msg, &enc_msg_size);
    openssl_ecies_encrypt(pub_eckey, kdp, kdp_len, NULL, 0, plaintext, plaintext_len, enc_msg, &enc_msg_size);
    DBG_DUMP(DBG_SEC, DBG_INFO, (void *)"encrypted", enc_msg, enc_msg_size);

    // Decrypted
    uint8_t dec_plaintext[2048] = {0};
    uint32_t dec_plaintext_len = 0;

    uint8_t *p_ciphertext, *p_cipher_R, *p_cipher_mac;
    uint32_t ciphertext_len;
    
    ASSERT_M (enc_msg_size >= (OPENSSL_ECIES_R_LEN+OPENSSL_ECIES_MAC_LEN));
    ciphertext_len = enc_msg_size - (OPENSSL_ECIES_R_LEN+OPENSSL_ECIES_MAC_LEN);
    p_ciphertext = enc_msg;
    p_cipher_R = &enc_msg[ciphertext_len];
    p_cipher_mac = &enc_msg[ciphertext_len+OPENSSL_ECIES_R_LEN];
    
    //openssl_ecies_decrypt_tmp(pri_eckey, p_ciphertext, ciphertext_len, p_cipher_R, p_cipher_mac, dec_plaintext, &dec_plaintext_len);
    openssl_ecies_decrypt(pri_eckey, kdp, kdp_len, NULL, 0, p_ciphertext, ciphertext_len, p_cipher_R, p_cipher_mac, dec_plaintext, &dec_plaintext_len);

    DBG_DUMP(DBG_SEC, DBG_INFO, (void *)"decrypted", dec_plaintext, dec_plaintext_len);
    //DBG_PRINT(DBG_SEC, DBG_INFO, (void *)"decrypted message: %s, msg_size: %d \n", dec_plaintext, dec_plaintext_len);

    BIO_free(pub_b);
    BIO_free(pri_b);
    EVP_PKEY_free(pri_pkey);
    EVP_PKEY_free(pub_pkey);
    EC_KEY_free(pub_eckey);
    EC_KEY_free(pri_eckey);

    EVP_cleanup(); // free OpenSSL_add_all_algorithms()
    ERR_free_strings(); // free ERR_load_crypto_strings()

    ret = SUCCESS_;

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    
    return (ret);
}
#endif // ECIES_TEST
