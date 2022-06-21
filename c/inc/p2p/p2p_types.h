/**
    @file p2p_types.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __P2P_TYPES_H__
#define __P2P_TYPES_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define MAC_ADDR_LEN        8

#define P2P_ADDR_LEN        8
#define P2P_ADDR_SUB_LEN    2

#define P2P_TIMESTAMP_LEN   8

#define P2P_SRVC_TYPE_GRP_BIT       0x8
#define P2P_SRVC_TYPE_GRP_MASK_     0x7
#define P2P_SRVC_TYPE_GRP_MASK      (P2P_SRVC_TYPE_GRP_MASK_ << P2P_SRVC_TYPE_GRP_BIT)
#define P2P_SRVC_TYPE_SET_GRP(a)    (((a) & P2P_SRVC_TYPE_GRP_MASK_) << P2P_SRVC_TYPE_GRP_BIT)
#define P2P_SRVC_TYPE_GET_GRP(a)    (((a) & P2P_SRVC_TYPE_GRP_MASK) >> P2P_SRVC_TYPE_GRP_BIT)

#define P2P_DEFAULT_ENC P2P_GRP_HDR_ENC_DISABLED

typedef uint8_t P2P_RESULT_E_TAG;
typedef enum
{
    P2P_RESULT_SUCCESS = 0x00,
    P2P_RESULT_FAILURE,
        
    P2P_RESULT_MAX
} P2P_RESULT_E;

#define P2P_VERSION     1
#define P2P_GRP_HDR_CRC ENABLED // ENABLED DISABLED

typedef enum
{
    P2P_GRP_HDR_ENC_DISABLED = 0x00, // Default
    P2P_GRP_HDR_ENC_ECIES,
    P2P_GRP_HDR_ENC_X25519,
    
    P2P_GRP_HDR_ENC_MAX
} P2P_GRP_HDR_ENC_E;

typedef enum
{
    P2P_TLV_HDR_TYPE_CMD = 0x00,
    P2P_TLV_HDR_TYPE_MGMT,
    P2P_TLV_HDR_TYPE_DATA,
    
    P2P_TLV_HDR_TYPE_MAX
} P2P_TLV_HDR_TYPE_E;


typedef enum
{
    P2P_SRVC_CMD_GROUP = P2P_SRVC_TYPE_SET_GRP(P2P_TLV_HDR_TYPE_CMD),
    P2P_SRVC_CMD_JOIN_REQ = P2P_SRVC_CMD_GROUP,
    P2P_SRVC_CMD_JOIN_RESP,
#if (P2P_PUBKEY_NOTI == ENABLED)
    P2P_SRVC_CMD_PUBKEY_NOTI,
#endif // P2P_PUBKEY_NOTI
    
    P2P_SRVC_MGMT_GROUP = P2P_SRVC_TYPE_SET_GRP(P2P_TLV_HDR_TYPE_MGMT),

    P2P_SRVC_DATA_GROUP = P2P_SRVC_TYPE_SET_GRP(P2P_TLV_HDR_TYPE_DATA),
    P2P_SRVC_DATA_REQ = P2P_SRVC_DATA_GROUP,
    P2P_SRVC_DATA_CFM,

    P2P_SRVC_MAX
} P2P_SRVC_E;

typedef enum
{
    P2P_NODE_TYPE_RN,
    P2P_NODE_TYPE_BN,
    P2P_NODE_TYPE_UN, // Unlicensed Node

    P2P_NODE_TYPE_MAX
} P2P_NODE_TYPE_E;

typedef enum
{
    P2P_NODE_RULE_NN  = 0x01,

    P2P_NODE_RULE_MAX
} P2P_NODE_RULE_E;

typedef struct
{
    uint8_t node_type; // P2P_NODE_TYPE_E
    uint8_t node_rule; // P2P_NODE_RULE_E
} __attribute__((__packed__)) P2P_NODE_T;

typedef struct
{
    P2P_NODE_T node;
    uint8_t  mac_addr[MAC_ADDR_LEN];
    uint32_t ip4_addr;
    uint64_t p2p_addr;
} __attribute__((__packed__)) P2P_NODE_INFO_T;

typedef struct
{
    uint64_t p2p_addr;
    uint16_t p2p_master_addr;
    uint16_t act_node_num; // Active Node Number
    uint16_t con_node_num; // Consensus Node Number
} __attribute__((__packed__)) P2P_CLUSTER_INFO_T;


//// from p2p.h
#define P2P_TEST DISABLED // ENABLED DISABLED
#define P2P_TEST_PINGPONG DISABLED // ENABLED DISABLED

#if (P2P_TEST == ENABLED)
#define P2P_DATA_IND_UP_LAYER DISABLED // ENABLED DISABLED
#else // P2P_TEST
#define P2P_DATA_IND_UP_LAYER ENABLED // ENABLED DISABLED
#endif // P2P_TEST

#define P2P_NULL_ADDR             0x0000000000000000
#define P2P_BCST_ADDR             0xFFFFFFFFFFFFFFFF
#define P2P_CLUSTER_ADDR_MASK     0x00000000FFFFFFFF
#define P2P_SUBNET_ADDR_MASK      0xFFFFFFFFFFFF0000
#define P2P_SUB_ADDR_MASK         0x000000000000FFFF
#define P2P_SUB_ROOT_ADDR         0x0000
#define P2P_UNIQ_KEY_MASK         0x00000000FFFF0000
#define P2P_UNIQ_KEY_IDX_BIT      16
#define P2P_GET_UNIQ_KEY(a)      (((a) & P2P_UNIQ_KEY_MASK) >> P2P_UNIQ_KEY_IDX_BIT)

typedef struct 
{
    uint64_t my_cluster_root;
    uint16_t my_uniq_addr;
    U64_U my_p2p_addr;
    uint16_t my_p2p_data_sn;
    uint16_t my_p2p_cmd_sn;
    P2P_NODE_T my_node_info;
    P2P_GRP_HDR_ENC_E my_enc_type;
} P2P_CNTX_T;

#ifndef IS_MY_SUBNET_ADDR //
#define IS_MY_SUBNET_ADDR(a,b) ((((a) & P2P_SUBNET_ADDR_MASK) == ((b) & P2P_SUBNET_ADDR_MASK)) ? true : false)
#endif 



#ifdef __cplusplus
}
#endif

#endif /* __P2P_TYPES_H__ */

