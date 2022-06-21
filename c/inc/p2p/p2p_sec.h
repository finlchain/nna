/**
    @file p2p_sec.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __P2P_SEC_H__
#define __P2P_SEC_H__

#ifdef __cplusplus
extern "C"
{
#endif

extern int32_t p2p_ecies_encrypt(      const char *p_pubkey_path, const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_plaintext, uint32_t plaintext_len, uint8_t **p_enc_msg, uint32_t *p_enc_msg_len);

extern int32_t p2p_ecies_decrypt(      const char *p_prikey_path, const uint8_t *p_p1, uint32_t p1_len, const uint8_t *p_p2, uint32_t p2_len, 
                                const uint8_t *p_enc_msg, uint32_t enc_msg_len, uint8_t **p_plaintext, uint32_t *p_plaintext_len);
#ifdef __cplusplus
}
#endif

#endif /* __P2P_SEC_H__ */

