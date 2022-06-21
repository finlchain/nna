/**
    @file openssl_util.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __OPENSSL_UTIL_H__
#define __OPENSSL_UTIL_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define SSL_PATH_SIZE 100

extern void openssl_init_v(void);
extern void openssl_get_version(void);

//
extern char *BN_bn2hex_z(const BIGNUM *a);

//
extern EVP_PKEY *EVP_PKEY_new_read_PRIKEY(bool b_enc, char *p_prikey_path);
extern EVP_PKEY *EVP_PKEY_new_read_PUBKEY(char *p_pubkey_path);
extern int32_t PEM_new_write_PUBKEY(char *p_pubkey_path, EVP_PKEY *pkey);
extern int32_t PEM_new_write_PRIKEY(char *p_prikey_path, EVP_PKEY *pkey);

//
extern int32_t PEM_write_raw_PUBKEY(char *p_pubkey_path, uint8_t *p_pubkey);

// IEEE-1363
// md :  the hash type
// share : input octct
// kdp : input key derivation parameters - can be null
// keylen : output desired length of key
// outkey : the derived key
extern int openssl_kdf2(const EVP_MD *md, const uint8_t *p_share, uint32_t share_len, const uint8_t *p_kdp, size_t kdp_len, uint32_t key_len, uint8_t *p_key);

extern uint32_t openssl_aes_cbc_encrypt(const uint8_t *plaintext, int32_t plaintext_len, uint8_t *key, uint8_t *iv, uint8_t *ciphertext);
extern uint32_t openssl_aes_cbc_decrypt(const uint8_t *ciphertext, int32_t ciphertext_len, uint8_t *key, uint8_t *iv, uint8_t *plaintext);

extern int32_t openssl_aes_encrpt_file(char *p_path, char *p_dst_path, uint8_t *p_seed, uint32_t seed_len);
extern uint8_t *openssl_aes_decrypt_file(char *p_path, uint8_t *p_seed, uint32_t seed_len);

extern int32_t openssl_aes_encrypt_pw(char *p_seed_path, uint8_t *p_pw, uint32_t pw_len, char *p_dst_path);
extern uint8_t *openssl_aes_decrypt_pw(char *p_seed_path, char *p_src_path, uint32_t *p_pw_len);

extern int32_t openssl_sha256(uint8_t *hash, uint8_t *data, uint32_t data_len);
extern int openssl_sha256_file(char* path, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif /* __OPENSSL_UTIL_H__ */
