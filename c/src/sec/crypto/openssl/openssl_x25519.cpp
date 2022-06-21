/**
    @file openssl_x25519.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#if (OPENSSL_111 == ENABLED)
uint8_t *openssl_111_x25519(const EVP_PKEY *p_prikey, const EVP_PKEY *p_peer_pub_key)
{
    int32_t ret = ERROR_;
	/* Generate shared secret */
	EVP_PKEY_CTX *ctx;
	uint8_t *skey = NULL;
	size_t skeylen;

    DBG_PRINT(DBG_SEC, DBG_TRACE, (void *)"(%s)\n",  __FUNCTION__);
    get_current_rss_monitor(DBG_INFO, (char *)"1");

	ctx = EVP_PKEY_CTX_new((EVP_PKEY *)p_prikey, NULL);
	if (!ctx) { 
		/* Error */
		DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"CTX is empty\n");

        return (NULL);
	}

    do
    {
    	if (EVP_PKEY_derive_init(ctx) <= 0) { 
    		/* Error */
    		DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"EVP derive initialization failed\n");
            break;
    	}
    	
    	if (EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY *)p_peer_pub_key) <= 0) { 
    		/* Error */
    		DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"EVP derive set peer failed\n");
            break;
    	}

    	/* Determine buffer length */
    	if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
    		/* Error */
    		DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"EVP derive failed\n");
            break;
    	}

        do
        {
        	skey = (unsigned char *)OPENSSL_malloc(skeylen);
        	if (!skey) {
        		/* Malloc failure */
        		DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"OpenSSL Malloc failed\n");
                break;
        	}

            do
            {
            	if (EVP_PKEY_derive(ctx, skey, &skeylen) <= 0) {
            		/* Error */
            		DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"Shared key derivation failed\n");
                    break;
            	}

                if (skeylen != X25519_SHARED_KEY_LEN_)
                {
                    /* Error */
            		DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"Shared key length error\n");
                    break;
                }

                DBG_DUMP(DBG_SEC, DBG_INFO, (void *) "Shared Secret Key", (uint8_t *)skey, skeylen);

                ret = SUCCESS_;
            } while(0);

            if (ret != SUCCESS_)
            {
                OPENSSL_free(skey);
            }
        } while(0);
    } while(0);

    EVP_PKEY_CTX_free(ctx);

    get_current_rss_monitor(DBG_INFO, (char *)"2");
    
    return (skey);
}
#endif // OPENSSL_111


int32_t openssl_x25519_encrypt(
#if (OPENSSL_111 == ENABLED)
                                const EVP_PKEY *p_prikey, const EVP_PKEY *p_peer_pubkey, 
#elif (OPENSSL_102 == ENABLED)
                                const uint8_t *p_prikey, const uint8_t *p_peer_pubkey, 
#endif // OPENSSL_111
                                const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_plaintext, uint32_t plaintext_len, uint8_t *p_enc_msg, uint32_t *p_enc_msg_len)
{
    int32_t ret = ERROR_;

    const EVP_MD *md = EVP_sha256();
    uint32_t cnt;
    uint32_t key_len_byte = OPENSSL_SYM_KEY_LEN;
    uint8_t key[key_len_byte*2], key_1[key_len_byte], key_2[key_len_byte];
    uint8_t mac_out[OPENSSL_X25519_MAC_LEN];
    uint8_t *p_S_out = NULL;

#if (OPENSSL_111 == ENABLED)
    p_S_out = openssl_111_x25519(p_prikey, p_peer_pubkey);
    ASSERT_M(p_S_out);
#elif (OPENSSL_102 == ENABLED)
    uint8_t password[X25519_SHARED_KEY_LEN_];

    p_S_out = password;

    X25519(p_S_out, p_prikey, p_peer_pubkey);
#endif // OPENSSL_111

    DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "S_out", (uint8_t *)p_S_out, X25519_SHARED_KEY_LEN_);

    openssl_kdf2(md, p_S_out, X25519_SHARED_KEY_LEN_, p_p1, p1_len, 2*key_len_byte, key);
    DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "kdf_key", (uint8_t *)key, 2*key_len_byte);

#if (OPENSSL_111 == ENABLED)
    OPENSSL_free(p_S_out);
#endif // OPENSSL_111

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

    if(*p_enc_msg_len)
    {
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

        if( len != OPENSSL_X25519_MAC_LEN)
        {
            DBG_PRINT(DBG_SEC, DBG_ERROR, (void *)"mac_size invalid(%d)\n",len); //error
            return (ret);
        }
        
        //DBG_DUMP(DBG_SEC, DBG_INFO, (void *) "ciphertext", (uint8_t *)p_enc_msg, *encrypted_msg_len);
        
        DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "mac_out", (uint8_t *)mac_out, OPENSSL_X25519_MAC_LEN);

        DBG_PRINT(DBG_SEC, DBG_INFO, (void *)"ciphertext_size(%d)\n", *p_enc_msg_len);

        MEMCPY_M(p_enc_msg + *p_enc_msg_len, mac_out, OPENSSL_X25519_MAC_LEN);
        *p_enc_msg_len += OPENSSL_X25519_MAC_LEN;

        //DBG_DUMP(DBG_SEC, DBG_NONE, (void *)"cipher", p_enc_msg, *p_enc_msg_len);
                    
        ret = SUCCESS_;
    }
    
    return (ret);
}

int32_t openssl_x25519_decrypt(
#if (OPENSSL_111 == ENABLED)
                                const EVP_PKEY *p_prikey, const EVP_PKEY *p_peer_pubkey, 
#elif (OPENSSL_102 == ENABLED)
                                const uint8_t *p_prikey, const uint8_t *p_peer_pubkey, 
#endif // OPENSSL_111
                                const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_ciphertext, uint32_t ciphertext_len, uint8_t *p_cipher_mac, 
                                uint8_t *p_plaintext, uint32_t *p_plaintext_len)
{
    int32_t ret = ERROR_;
    uint8_t *p_S_out;

    const EVP_MD *md = EVP_sha256();
    uint32_t cnt;
    uint32_t key_len_byte = OPENSSL_SYM_KEY_LEN;
    uint8_t key[key_len_byte*2], key_1[key_len_byte], key_2[key_len_byte];
    uint8_t mac_out[OPENSSL_X25519_MAC_LEN];

    DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "ciphertext", (uint8_t *)p_ciphertext, ciphertext_len);
    DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "mac_in", (uint8_t *)p_cipher_mac, OPENSSL_X25519_MAC_LEN);

#if (OPENSSL_111 == ENABLED)
    p_S_out = openssl_111_x25519(p_prikey, p_peer_pubkey);
    ASSERT_M(p_S_out);
#elif (OPENSSL_102 == ENABLED)
    uint8_t password[X25519_SHARED_KEY_LEN_];

    p_S_out = password;
    
    X25519(p_S_out, p_prikey, p_peer_pubkey);
#endif // OPENSSL_111

    openssl_kdf2(md, p_S_out, X25519_SHARED_KEY_LEN_, p_p1, p1_len, 2*key_len_byte, key);
    DBG_DUMP(DBG_SEC, DBG_NONE, (void *) "kdf_key", (uint8_t *)key, 2*key_len_byte);

#if (OPENSSL_111 == ENABLED)
    OPENSSL_free(p_S_out);
#endif // OPENSSL_111

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

    if (*p_plaintext_len)
    {
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
    }

    return (ret);
}

int32_t openssl_x25519_keygen(char *p_path)
{
    int32_t ret = ERROR_;    

#if (OPENSSL_111 == ENABLED)
    ret = openssl_111_25519_keygen(p_path, NID_X25519);
#elif (OPENSSL_102 == ENABLED)
    uint8_t pubkey[X25519_PUBLIC_KEY_LEN_], prikey[X25519_PRIVATE_KEY_LEN_];

    X25519_keypair(pubkey, prikey);

    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"x prikey", prikey, X25519_PRIVATE_KEY_LEN_);
    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"x pubkey", pubkey, X25519_PUBLIC_KEY_LEN_);

    if (p_path)
    {
        char pubkey_dir[SSL_PATH_SIZE];
        char prikey_dir[SSL_PATH_SIZE];
        
        sprintf((char *)pubkey_dir, "%s%s", p_path, (char *)"x_pubkey.hex");
        sprintf((char *)prikey_dir, "%s%s", p_path, (char *)"x_privkey.hex");
        
        util_hex_file_wb(pubkey_dir, pubkey, X25519_PUBLIC_KEY_LEN_);
        util_hex_file_wb(prikey_dir, prikey, X25519_PRIVATE_KEY_LEN_);

        ret = SUCCESS_;
    }
#endif // OPENSSL_111

    return (ret);
}

#if (X25519_TEST == ENABLED)
int32_t openssl_x25519_key_test(void)
{
    int32_t ret = ERROR_;
#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_xa_prikey, *p_xa_pubkey, *p_xb_prikey, *p_xb_pubkey;
    uint8_t *p_key_aS, *p_key_bS;

    ret = openssl_x25519_keygen((char *)"key/xa_");

    ret = openssl_x25519_keygen((char *)"key/xb_");

    p_xa_prikey = EVP_PKEY_new_read_PRIKEY(false, (char *)"key/xa_privkey.pem");
    ASSERT_M(p_xa_prikey);
    p_xa_pubkey = EVP_PKEY_new_read_PUBKEY((char *)"key/xa_pubkey.pem");
    ASSERT_M(p_xa_pubkey);
    
    p_xb_prikey = EVP_PKEY_new_read_PRIKEY(false, (char *)"key/xb_privkey.pem");
    ASSERT_M(p_xb_prikey);
    p_xb_pubkey = EVP_PKEY_new_read_PUBKEY((char *)"key/xb_pubkey.pem");
    ASSERT_M(p_xb_pubkey);

    p_key_aS = openssl_111_x25519(p_xa_prikey, p_xb_pubkey);
    p_key_bS = openssl_111_x25519(p_xb_prikey, p_xa_pubkey);

    EVP_PKEY_free(p_xa_prikey);
    EVP_PKEY_free(p_xa_pubkey);
    EVP_PKEY_free(p_xb_prikey);
    EVP_PKEY_free(p_xb_pubkey);

    OPENSSL_free(p_key_aS);
    OPENSSL_free(p_key_bS);
#elif (OPENSSL_102 == ENABLED)
    uint8_t pubkey_a[X25519_PUBLIC_KEY_LEN_], prikey_a[X25519_PRIVATE_KEY_LEN], key_aS[X25519_SHARED_KEY_LEN_];
    uint8_t pubkey_b[X25519_PUBLIC_KEY_LEN_], prikey_b[X25519_PRIVATE_KEY_LEN], key_bS[X25519_SHARED_KEY_LEN_];

    X25519_keypair(pubkey_a, prikey_a);
    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"a pri", prikey_a, X25519_PRIVATE_KEY_LEN_);
    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"a pub", pubkey_a, X25519_PUBLIC_KEY_LEN_);

    X25519_keypair(pubkey_b, prikey_b);
    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"b pri", prikey_b, X25519_PRIVATE_KEY_LEN_);
    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"b pub", pubkey_b, X25519_PUBLIC_KEY_LEN_);

    X25519(key_aS, prikey_a, pubkey_b);
    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"a S", key_aS, X25519_SHARED_KEY_LEN_);

    X25519(key_bS, prikey_b, pubkey_a);
    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"b S", key_bS, X25519_SHARED_KEY_LEN_);

    ret = SUCCESS_;
#endif // OPENSSL_111

    return (ret);
}
int32_t openssl_x25519_test(void) 
{
    int32_t ret = ERROR_;

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY *p_xa_prikey, *p_xa_pubkey, *p_xb_prikey, *p_xb_pubkey;
#elif (OPENSSL_102 == ENABLED)
    uint8_t pubkey_a[X25519_PUBLIC_KEY_LEN_], prikey_a[X25519_PRIVATE_KEY_LEN_];
    uint8_t pubkey_b[X25519_PUBLIC_KEY_LEN_], prikey_b[X25519_PRIVATE_KEY_LEN_];
#endif // OPENSSL_111

    uint8_t plaintext[2048];
    uint32_t plaintext_len;
    
    uint8_t enc_msg[2048];
    uint32_t enc_msg_len;

    uint8_t kdp[16] = { 0x75, 0xEE, 0xF8, 0x1A, 0xA3, 0x04, 0x1E, 0x33, 0xB8, 0x09, 0x71, 0x20, 0x3D, 0x2C, 0x0C, 0x52 };
    uint32_t kdp_len = 16;
    
    for (plaintext_len=0; plaintext_len<100; plaintext_len++)
    {
        plaintext[plaintext_len] = plaintext_len;
    }

    DBG_DUMP(DBG_SEC, DBG_INFO, (void *)"plaintext", plaintext, plaintext_len);

#if (OPENSSL_111 == ENABLED)
    //
    ret = openssl_x25519_keygen((char *)"key/xa_");

    //
    p_xa_prikey = EVP_PKEY_new_read_PRIKEY(false, (char *)"key/xa_privkey.pem");
    ASSERT_M(p_xa_prikey);
    p_xa_pubkey = EVP_PKEY_new_read_PUBKEY((char *)"key/xa_pubkey.pem");
    ASSERT_M(p_xa_pubkey);
#elif (OPENSSL_102 == ENABLED)
    X25519_keypair(pubkey_a, prikey_a);

    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"a pri", prikey_a, X25519_PRIVATE_KEY_LEN_);
    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"a pub", pubkey_a, X25519_PUBLIC_KEY_LEN_);
#endif // OPENSSL_111

#if (OPENSSL_111 == ENABLED)
    //
    ret = openssl_x25519_keygen((char *)"key/xb_");

    //
    p_xb_prikey = EVP_PKEY_new_read_PRIKEY(false, (char *)"key/xb_privkey.pem");
    ASSERT_M(p_xb_prikey);
    p_xb_pubkey = EVP_PKEY_new_read_PUBKEY((char *)"key/xb_pubkey.pem");
    ASSERT_M(p_xb_pubkey);
#elif (OPENSSL_102 == ENABLED)
    X25519_keypair(pubkey_b, prikey_b);

    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"b pri", prikey_b, X25519_PRIVATE_KEY_LEN_);
    DBG_DUMP(DBG_CLI, DBG_INFO, (void *)"b pub", pubkey_b, X25519_PUBLIC_KEY_LEN_);
#endif // OPENSSL_111

    // Encrypted
    openssl_x25519_encrypt(
#if (OPENSSL_111 == ENABLED)
                p_xa_prikey, p_xb_pubkey, 
#elif (OPENSSL_102 == ENABLED)
                prikey_a, pubkey_b, 
#endif // OPENSSL_111
                kdp, kdp_len, NULL, 0, plaintext, plaintext_len, enc_msg, &enc_msg_len);
    DBG_DUMP(DBG_SEC, DBG_INFO, (void *)"encrypted", enc_msg, enc_msg_len);
    
    // Decrypted
    uint8_t dec_plaintext[2048] = {0};
    uint32_t dec_plaintext_len = 0;

    uint8_t *p_ciphertext, *p_cipher_mac;
    uint32_t ciphertext_len;
    
    ASSERT_M (enc_msg_len >= (OPENSSL_X25519_MAC_LEN));
    ciphertext_len = enc_msg_len - (OPENSSL_X25519_MAC_LEN);
    p_ciphertext = enc_msg;
    p_cipher_mac = &enc_msg[ciphertext_len];
    
    openssl_x25519_decrypt(
#if (OPENSSL_111 == ENABLED)
                p_xb_prikey, p_xa_pubkey, 
#elif (OPENSSL_102 == ENABLED)
                prikey_b, pubkey_a, 
#endif // OPENSSL_111
                kdp, kdp_len, NULL, 0, p_ciphertext, ciphertext_len, p_cipher_mac, dec_plaintext, &dec_plaintext_len);

    DBG_DUMP(DBG_SEC, DBG_INFO, (void *)"decrypted", dec_plaintext, dec_plaintext_len);

#if (OPENSSL_111 == ENABLED)
    EVP_PKEY_free(p_xa_prikey);
    EVP_PKEY_free(p_xa_pubkey);
    EVP_PKEY_free(p_xb_prikey);
    EVP_PKEY_free(p_xb_pubkey);
#endif // OPENSSL_111

    ret = SUCCESS_;
    
    return (ret);
}
#endif // X25519_TEST

