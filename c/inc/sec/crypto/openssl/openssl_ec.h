/**
    @file openssl_ec.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __OPENSSL_EC_H__
#define __OPENSSL_EC_H__

#ifdef __cplusplus
extern "C"
{
#endif

extern int32_t g_ec_algo;

//
extern EC_KEY *EC_KEY_new_raw_PUBKEY(uint8_t *p_pubkey);
extern ECDSA_SIG *ECDSA_SIG_new_raw_SIG(SSL_SIG_U *p_sig_hex);
extern int32_t raw_SIG_new_ECDSA_SIG(ECDSA_SIG *sig, SSL_SIG_U *p_sig_hex);
extern int32_t ECDSA_new_do_verify(uint8_t *p_data, uint32_t data_len, ECDSA_SIG *p_sig, EC_KEY *p_eckey);

//
extern int32_t openssl_ec_pubkey_pem2hex(char *p_pubkey_path, uint8_t *p_pubkey);
extern int32_t openssl_ec_pubkey_hex2pem(char *p_pubkey_path, uint8_t *p_pubkey);

//
extern int32_t openssl_ec_key_gen(char *p_path);
extern int32_t openssl_ec_pubkey_gen(char *_pri_key);

//
extern int32_t openssl_ec_pubkey_decompress(char *p_comp_pubkey, char *p_uncomp_pubkey);
extern int32_t openssl_ec_pubkey_compress(char *p_uncomp_pubkey, char *p_comp_pubkey);

#ifdef __cplusplus
}
#endif

#endif /* __OPENSSL_EC_H__ */
