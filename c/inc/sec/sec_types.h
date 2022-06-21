/**
    @file sec_types.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __SEC_TYPES_H__
#define __SEC_TYPES_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define HASH_SIZE           32
#define HASH_STR_DATA_SIZE  (HASH_SIZE * 2)
#define HASH_STR_SIZE       (HASH_STR_DATA_SIZE + 1)
    
#define SIG_SIZE        64
#define SIG_STR_SIZE    (SIG_SIZE*2+1)
    
#define SIG_R_SIZE      32
#define SIG_S_SIZE      32
    
#define SIG_R_STR_SIZE (SIG_R_SIZE*2+1)
#define SIG_S_STR_SIZE (SIG_S_SIZE*2+1)
    
#define COMP_PUBKEY_SIZE    33
#define UNCOMP_PUBKEY_SIZE  65
    
#define COMP_PUBKEY_STR_SIZE    (COMP_PUBKEY_SIZE*2+1)
#define UNCOMP_PUBKEY_STR_SIZE  (UNCOMP_PUBKEY_SIZE*2+1)
    
#define PUBKEY_DELIMITER_EC_COMP_EVEN   0x02
#define PUBKEY_DELIMITER_EC_COMP_ODD    0x03
#define PUBKEY_DELIMITER_EC_UNCOMP      0x04
#define PUBKEY_DELIMITER_25519          0x05 // Defined by ourself.

typedef union
{
    struct
    {
        uint8_t r[SIG_R_SIZE];
        uint8_t s[SIG_S_SIZE];
    } ec;
    uint8_t sig[SIG_SIZE];
} __attribute__((__packed__)) SSL_SIG_U;
    
#define SSL_VERIFY_SUCCESS 1
#define SSL_VERIFY_INCORRECT 0
#define SSL_VERIFY_ERROR -1

#ifdef __cplusplus
}
#endif

#endif /* __SEC_TYPES_H__ */
