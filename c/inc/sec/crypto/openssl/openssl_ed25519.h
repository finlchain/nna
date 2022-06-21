/**
    @file openssl_ed25519.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __OPENSSL_ED25519_H__
#define __OPENSSL_ED25519_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define ED25519_TEST DISABLED // ENABLED DISABLED

#define ED25519_PRIKEY_OFFSET 0
#define ED25519_PUBKEY_OFFSET 32

//
extern int32_t openssl_ed_pubkey_pem2hex(char *p_pubkey_path, uint8_t *p_pubkey);
extern int32_t openssl_ed_pubkey_hex2pem(char *p_pubkey_path, uint8_t *p_pubkey);

//
extern int32_t openssl_ed25519_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_pubkey);
extern int32_t openssl_ed25519_verify_pubkey_path(char *p_pubkey_path, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex) ;
extern int32_t openssl_ed25519_sig(bool b_enc, char *p_prikey_path, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex);

extern int32_t openssl_ed25519_keygen(char *p_path);

#if (ED25519_TEST == ENABLED)
int32_t openssl_ed25519_test(void); 
#endif // ED25519_TEST



#ifdef __cplusplus
}
#endif

#endif /* __OPENSSL_ED25519_H__ */
