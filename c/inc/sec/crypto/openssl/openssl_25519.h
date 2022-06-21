/**
    @file openssl_25519.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __OPENSSL_25519_H__
#define __OPENSSL_25519_H__

#ifdef __cplusplus
extern "C"
{
#endif

#if (OPENSSL_111 == ENABLED)
//
extern void openssl_111_print_25519_prikey(EVP_PKEY *p_pkey);
extern void openssl_111_print_25519_pubkey(EVP_PKEY *p_pkey);
//
extern int32_t openssl_111_get_25519_prikey(EVP_PKEY *p_pkey, uint8_t *p_prikey);
extern int32_t openssl_111_get_25519_pubkey(EVP_PKEY *p_pkey, uint8_t *p_pubkey);
//
extern int32_t openssl_111_25519_keygen(char *p_path, int32_t type);
#endif // OPENSSL_111

#ifdef __cplusplus
}
#endif

#endif /* __OPENSSL_25519_H__ */
