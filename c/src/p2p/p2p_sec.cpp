/**
    @file p2p_sec.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

int32_t p2p_ecies_encrypt(      const char *p_pubkey_path, const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_plaintext, uint32_t plaintext_len, uint8_t **p_enc_msg, uint32_t *p_enc_msg_len)
{
    int32_t ret = ERROR_;

    FILE* fp_in;
    
    fp_in = fopen (p_pubkey_path, "r");
    if (!fp_in) return (ret);

    do
    {
        EVP_PKEY *p_pub_key_in = NULL;

        p_pub_key_in = PEM_read_PUBKEY(fp_in, NULL, NULL, NULL);

        if(!p_pub_key_in) break;

        do
        {
            EC_KEY *p_pubkey = EVP_PKEY_get1_EC_KEY(p_pub_key_in);
            if(!p_pubkey) break;

            do
            {
                uint32_t alloc_len = 0;

                if (*p_enc_msg == NULL)
                {
                    alloc_len = CEIL(plaintext_len, AES_BLOCK_SIZE)+OPENSSL_ECIES_R_LEN+OPENSSL_ECIES_MAC_LEN;
                    if (!IS_REMAINDER(plaintext_len, AES_BLOCK_SIZE))
                    {
                        alloc_len += AES_BLOCK_SIZE;
                    }
                    DBG_PRINT (DBG_P2P, DBG_NONE, (void *)"CEIL(%d), R_LEN(%d), MAC_LEN(%d)\n", CEIL(plaintext_len, AES_BLOCK_SIZE), OPENSSL_ECIES_R_LEN, OPENSSL_ECIES_MAC_LEN);
                    
                    *p_enc_msg = (uint8_t *)MALLOC_M(alloc_len);
                }
                
                ret = openssl_ecies_encrypt(p_pubkey, p_p1, p1_len, p_p2, p2_len, p_plaintext, plaintext_len, *p_enc_msg, p_enc_msg_len);

                if ((ret == ERROR_) && (alloc_len))
                {
                    FREE_M(*p_enc_msg);
                }
            } while (0);
            EC_KEY_free(p_pubkey);
            
        } while (0);

        EVP_PKEY_free(p_pub_key_in);
    } while(0);

    fclose (fp_in);

    return (ret);
}

int32_t p2p_ecies_decrypt(      const char *p_prikey_path, const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_enc_msg, uint32_t enc_msg_len, uint8_t **p_plaintext, uint32_t *p_plaintext_len)
{
    int32_t ret = ERROR_;

    FILE* fp_in;
    
    fp_in = fopen (p_prikey_path, "r");
    if (!fp_in) return (ret);

    do
    {
        EVP_PKEY *p_prikey_in = NULL;

        p_prikey_in = PEM_read_PrivateKey(fp_in, NULL, NULL, NULL);

        if(!p_prikey_in) break;

        do
        {
            EC_KEY *p_prikey = EVP_PKEY_get1_EC_KEY(p_prikey_in);
            if(!p_prikey) break;

            if (enc_msg_len >= (OPENSSL_ECIES_R_LEN + OPENSSL_ECIES_MAC_LEN))
            {
                const uint8_t *p_ciphertext, *p_cipher_R, *p_cipher_mac;
                uint32_t ciphertext_len;
                bool alloc_p = false;

                ciphertext_len = enc_msg_len - (OPENSSL_ECIES_R_LEN + OPENSSL_ECIES_MAC_LEN);

                p_ciphertext = p_enc_msg;
                p_cipher_R = &p_enc_msg[ciphertext_len];
                p_cipher_mac = &p_enc_msg[ciphertext_len+OPENSSL_ECIES_R_LEN];

                if (*p_plaintext == NULL)
                {
                    *p_plaintext = (uint8_t *)MALLOC_M(ciphertext_len);
                    ASSERT_M(*p_plaintext);
                    alloc_p = true;
                }
                
                ret = openssl_ecies_decrypt(p_prikey, p_p1, p1_len, p_p2, p2_len, p_ciphertext, ciphertext_len, p_cipher_R, p_cipher_mac, *p_plaintext, p_plaintext_len);

                if ((ret == ERROR_) && (alloc_p == true))
                {
                    FREE_M(*p_plaintext);
                }
            }
            else
            {
                ASSERT_M(0);
            }
            
            EC_KEY_free(p_prikey);
        } while (0);

        EVP_PKEY_free(p_prikey_in);
    } while (0);

    fclose (fp_in);

    return (ret);
}
                                
