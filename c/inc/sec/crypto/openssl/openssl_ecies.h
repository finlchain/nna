/**
    @file openssl_ecies.h
    @date 2019/01/22
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __OPENSSL_ECIES_H__
#define __OPENSSL_ECIES_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define ECIES_TEST ENABLED // ENABLED DISABLED

#define OPENSSL_ECIES_R_LEN COMP_PUBKEY_SIZE
#define OPENSSL_ECIES_S_LEN 32
#define OPENSSL_ECIES_MAC_LEN 32
#define OPENSSL_SYM_KEY_LEN 16 /**< Symmetric Key size - 128 bits */
#define OPENSSL_ECIES_P2_LEN 8

extern int32_t openssl_ecies_encrypt(const EC_KEY *p_pubkey, const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_plaintext, uint32_t plaintext_len, uint8_t *p_enc_msg, uint32_t *p_enc_msg_len);

extern int32_t openssl_ecies_decrypt(const EC_KEY *p_prikey, const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                    const uint8_t *p_ciphertext, uint32_t ciphertext_len, const uint8_t *p_cipher_R, const uint8_t *p_cipher_mac, 
                                    uint8_t *p_plaintext, uint32_t *p_plaintext_len);

#if (ECIES_TEST == ENABLED)
extern int openssl_ecies_test(void);
#endif // ECIES_TEST

#ifdef __cplusplus
}
#endif

#endif /* __OPENSSL_ECIES_H__ */
