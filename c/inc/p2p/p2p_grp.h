/**
    @file p2p_grp.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __P2P_GRP_H__
#define __P2P_GRP_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define P2P_LEN_MAX             TX_LEN_MAX
#define P2P_SEQ_NUM_OVERFLOW    (0xFFFF/2)

// Group Header
#define P2P_GRP_HDR_LEN sizeof(P2P_GRP_HDR_T)

#define P2P_GRP_HDR_CRC_BIT         0
#define P2P_GRP_HDR_CRC_MASK_       0x1
#define P2P_GRP_HDR_CRC_MASK        (P2P_GRP_HDR_CRC_MASK_ << P2P_GRP_HDR_CRC_BIT)
#define P2P_GRP_HDR_SET_CRC(a)      (((a)&P2P_GRP_HDR_CRC_MASK_) << P2P_GRP_HDR_CRC_BIT)
#define P2P_GRP_HDR_GET_CRC(a)      (((a)&P2P_GRP_HDR_CRC_MASK) >> P2P_GRP_HDR_CRC_BIT)

#define P2P_GRP_HDR_ENC_BIT         1
#define P2P_GRP_HDR_ENC_MASK_       0x3
#define P2P_GRP_HDR_ENC_MASK        (P2P_GRP_HDR_ENC_MASK_ << P2P_GRP_HDR_ENC_BIT)
#define P2P_GRP_HDR_SET_ENC(a)      (((a)&P2P_GRP_HDR_ENC_MASK_) << P2P_GRP_HDR_ENC_BIT)
#define P2P_GRP_HDR_GET_ENC(a)      (((a)&P2P_GRP_HDR_ENC_MASK) >> P2P_GRP_HDR_ENC_BIT)

#define P2P_GRP_HDR_VER_BIT         3
#define P2P_GRP_HDR_VER_MASK_       0x1F
#define P2P_GRP_HDR_VER_MASK        (P2P_GRP_HDR_VER_MASK_ << P2P_GRP_HDR_VER_BIT)
#define P2P_GRP_HDR_SET_VER(a)      (((a)&P2P_GRP_HDR_VER_MASK_) << P2P_GRP_HDR_VER_BIT)
#define P2P_GRP_HDR_GET_VER(a)      (((a)&P2P_GRP_HDR_VER_MASK) >> P2P_GRP_HDR_VER_BIT)

// TLV Header
#define P2P_TLV_HDR_NEXT_BIT        31
#define P2P_TLV_HDR_NEXT_MASK_      0x1
#define P2P_TLV_HDR_NEXT_MASK       (P2P_TLV_HDR_NEXT_MASK_ << P2P_TLV_HDR_NEXT_BIT)
#define P2P_TLV_HDR_SET_NEXT(a)     (((a)&P2P_TLV_HDR_NEXT_MASK_) << P2P_TLV_HDR_NEXT_BIT)
#define P2P_TLV_HDR_GET_NEXT(a)     (((a)&P2P_TLV_HDR_NEXT_MASK) >> P2P_TLV_HDR_NEXT_BIT)

#define P2P_TLV_HDR_TYPE_BIT        28
#define P2P_TLV_HDR_TYPE_MASK_      0x7
#define P2P_TLV_HDR_TYPE_MASK       (P2P_TLV_HDR_TYPE_MASK_ << P2P_TLV_HDR_TYPE_BIT)
#define P2P_TLV_HDR_SET_TYPE(a)     (((a)&P2P_TLV_HDR_TYPE_MASK_) << P2P_TLV_HDR_TYPE_BIT)
#define P2P_TLV_HDR_GET_TYPE(a)     (((a)&P2P_TLV_HDR_TYPE_MASK) >> P2P_TLV_HDR_TYPE_BIT)

#define P2P_TLV_HDR_CMD_BIT         20
#define P2P_TLV_HDR_CMD_MASK_       0xFF
#define P2P_TLV_HDR_CMD_MASK        (P2P_TLV_HDR_CMD_MASK_ << P2P_TLV_HDR_CMD_BIT)
#define P2P_TLV_HDR_SET_CMD(a)      (((a)&P2P_TLV_HDR_CMD_MASK_) << P2P_TLV_HDR_CMD_BIT)
#define P2P_TLV_HDR_GET_CMD(a)      (((a)&P2P_TLV_HDR_CMD_MASK) >> P2P_TLV_HDR_CMD_BIT)

#define P2P_TLV_HDR_TYPE_CMD_BIT    20
#define P2P_TLV_HDR_TYPE_CMD_MASK_  0x7FF
#define P2P_TLV_HDR_TYPE_CMD_MASK   (P2P_TLV_HDR_TYPE_CMD_MASK_ << P2P_TLV_HDR_TYPE_CMD_BIT)
#define P2P_TLV_HDR_SET_TYPE_CMD(a) (((a)&P2P_TLV_HDR_TYPE_CMD_MASK_) << P2P_TLV_HDR_TYPE_CMD_BIT)
#define P2P_TLV_HDR_GET_TYPE_CMD(a) (((a)&P2P_TLV_HDR_TYPE_CMD_MASK) >> P2P_TLV_HDR_TYPE_CMD_BIT)

#define P2P_TLV_HDR_LEN_BIT         8
#define P2P_TLV_HDR_LEN_MASK_       0xFFF
#define P2P_TLV_HDR_LEN_MASK        (P2P_TLV_HDR_LEN_MASK_ << P2P_TLV_HDR_LEN_BIT)
#define P2P_TLV_HDR_SET_LEN(a)      (((a)&P2P_TLV_HDR_LEN_MASK_) << P2P_TLV_HDR_LEN_BIT)
#define P2P_TLV_HDR_GET_LEN(a)      (((a)&P2P_TLV_HDR_LEN_MASK) >> P2P_TLV_HDR_LEN_BIT)

#define P2P_TLV_HDR_RSVD_BIT        0
#define P2P_TLV_HDR_RSVD_MASK_      0xFF
#define P2P_TLV_HDR_RSVD_MASK       (P2P_TLV_HDR_RSVD_MASK_ << P2P_TLV_HDR_RSVD_BIT)
#define P2P_TLV_HDR_SET_RSVD_LEN(a) (((a)&P2P_TLV_HDR_RSVD_MASK_) << P2P_TLV_HDR_RSVD_BIT)
#define P2P_TLV_HDR_GET_RSVD_LEN(a) (((a)&P2P_TLV_HDR_RSVD_MASK) >> P2P_TLV_HDR_RSVD_BIT)

typedef struct
{
    uint64_t dst_addr;
    uint64_t src_addr;
    uint64_t timestamp; // UTC(ms)
    uint32_t info;
    uint16_t seq_num;
    uint16_t len;
} __attribute__((__packed__)) P2P_GRP_HDR_T;

typedef struct
{
    //            <------------- MSB      LSB --------------->
    // tlv : 1bit Next, 3bit Type, 8bit Cmd, 12bit Len, 8bit Reserved
    uint32_t tlv;
} __attribute__((__packed__)) P2P_GRP_TLV_HDR_T;

typedef struct
{
    P2P_GRP_HDR_T grp_hdr;
    P2P_GRP_TLV_HDR_T tlv_hdr;
} __attribute__((__packed__)) P2P_COM_HDR_T;

typedef struct
{
    P2P_GRP_TLV_HDR_T tlv_hdr;
    
    uint8_t buf[0];
} __attribute__((__packed__)) P2P_SUB_HDR_T;

////
typedef struct
{
    P2P_GRP_HDR_T grp_hdr;
    
    uint8_t buf[0];
} __attribute__((__packed__)) P2P_SRVC_REQ_T;

typedef struct
{
    P2P_GRP_HDR_T grp_hdr;
    
    uint8_t buf[0];
} __attribute__((__packed__)) P2P_SRVC_CFM_T;

typedef struct
{
    P2P_GRP_HDR_T grp_hdr;
    
    uint8_t buf[0];
} __attribute__((__packed__)) P2P_SRVC_IND_T;


#ifdef __cplusplus
}
#endif

#endif /* __P2P_GRP_H__ */

