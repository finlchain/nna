/**
    @file openssl_ecdsa.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __OPENSSL_ECDSA_H__
#define __OPENSSL_ECDSA_H__

#ifdef __cplusplus
extern "C"
{
#endif

extern int32_t openssl_ecdsa_verify(uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex, uint8_t *p_comp_pubkey);
extern int32_t openssl_ecdsa_verify_pubkey_path(char *p_pubkey_path, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex);
extern int32_t openssl_ecdsa_sig(bool b_enc, char *p_prikey_path, uint8_t *p_data, uint32_t data_len, SSL_SIG_U *p_sig_hex);


#ifdef __cplusplus
}
#endif

#endif /* __OPENSSL_ECDSA_H__ */
