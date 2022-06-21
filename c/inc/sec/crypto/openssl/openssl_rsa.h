/**
    @file openssl_rsa.h
    @date 2019/01/22
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __OPENSSL_RSA_H__
#define __OPENSSL_RSA_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define RSA_KEY_VALID 1

extern int32_t openssl_rsa_msg_encrypt(char *rsa_pubkey_path, const unsigned char *plain_msg, int plain_msg_size, unsigned char *cipher_msg, int *cipher_msg_size);

extern int32_t openssl_rsa_msg_decrypt(char *rsa_privkey_path, const unsigned char *cipher_msg, int cipher_msg_size, unsigned char *plain_msg, int *plain_msg_size);

extern int32_t openssl_rsa_keypair_gen(void);

#ifdef __cplusplus
}
#endif

#endif /* __OPENSSL_RSA_H__ */
