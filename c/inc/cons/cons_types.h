/**
    @file cons_types.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __CONS_TYPES_H__
#define __CONS_TYPES_H__

#ifdef __cplusplus
extern "C"
{
#endif

//
#define BLK_NUM_SIZE            8
#define BLK_NUM_STR_DATA_SIZE   (BLK_NUM_SIZE * 2)
#define BLK_NUM_STR_SIZE        (BLK_NUM_STR_DATA_SIZE + 1)

#define BLK_NUM_INIT_VAL        0

//
#define BGT_SIZE                8
#define BGT_STR_DATA_SIZE       (BGT_SIZE * 2)
#define BGT_STR_SIZE            (BGT_STR_DATA_SIZE + 1)

//
#define DB_KEY_SIZE             8
#define DB_KEY_STR_DATA_SIZE    (DB_KEY_SIZE * 2)
#define DB_KEY_STR_SIZE         (DB_KEY_STR_DATA_SIZE + 1)

#define DB_KEY_VAL_MASK 0x0000FFFFFFFFFFFF
#define DB_KEY_MINUS(a,b) (((a) & DB_KEY_VAL_MASK) - ((b) & DB_KEY_VAL_MASK))

//
#define TX_SIZE                     sizeof(CONS_TX_INFO_T)
#define TX_STR_SIZE                 (TX_SIZE*2)
#define TX_CNT_SIZE                 (BYTE_4)
#define TX_CNT_STR_SIZE             (TX_CNT_SIZE * 2 + 1)
#define TX_CNT_STR_DATA_SIZE        (TX_CNT_SIZE * 2)

//
#define CONS_USE_SUBNET_ID          DISABLED // ENABLED DISABLED

#define CONS_SUBNET_ID_MASK         0xFFFF000000000000
#define CONS_SUBNET_ID_MASK_        0xFFFF
#define CONS_SUBNET_ID_IDX_BIT      48
#define CONS_SET_SUBNET_ID(a)       ((uint64_t)((uint64_t)((uint64_t)(a) & CONS_SUBNET_ID_MASK_) << CONS_SUBNET_ID_IDX_BIT))
#define CONS_GET_SUBNET_ID(a)       (((a) & CONS_SUBNET_ID_MASK) >> CONS_SUBNET_ID_IDX_BIT)

//
#define CONS_TO_DB_TASK         ENABLED // ENABLED DISABLED
#define CONS_TX_ACK             ENABLED // ENABLED DISABLED
#define CONS_TX_ACK_SEPARATED   DISABLED // ENABLED DISABLED

#define CONS_PEER_MAX       1
#define CONS_PEER_NN_IDX    0

#define CONS_PATH_SIZE      100
#define CONS_PK_NAME_SIZE   20
#define CONS_DIR_SIZE       (CONS_PATH_SIZE - CONS_PK_NAME_SIZE)

#define CONS_1ST_NN_IDX     0
#define CONS_NN_MAX         256
#define CONS_CN_MAX         100

#define CONS_TX_INFO_MAX    3 // MAX = 30

#define CONS_TIER_0         0
#define CONS_TIER_MAX       1

#define CONS_TCP_TYPE       1
#define CONS_UDP_TYPE       2

//
#define CONS_SRVC_CMDTYPE_GRP_BIT    0x0
#define CONS_SRVC_CMDTYPE_GRP_MASK_  0xFFF
#define CONS_SRVC_CMDTYPE_GRP_MASK   (CONS_SRVC_CMDTYPE_GRP_MASK_ << CONS_SRVC_CMDTYPE_GRP_BIT)
#define CONS_SRVC_CMDTYPE_SET_GRP(a) (((a) & CONS_SRVC_CMDTYPE_GRP_MASK_) << CONS_SRVC_CMDTYPE_GRP_BIT)
#define CONS_SRVC_CMDTYPE_GET_GRP(a) (((a) & CONS_SRVC_CMDTYPE_GRP_MASK) >> CONS_SRVC_CMDTYPE_GRP_BIT)

#define CONS_SRVC_CMD_GRP_BIT        0x0
#define CONS_SRVC_CMD_GRP_MASK_      0xFF
#define CONS_SRVC_CMD_GRP_MASK       (CONS_SRVC_CMD_GRP_MASK_ << CONS_SRVC_CMD_GRP_BIT)
#define CONS_SRVC_CMD_SET_GRP(a)     (((a) & CONS_SRVC_CMD_GRP_MASK_) << CONS_SRVC_CMD_GRP_BIT)
#define CONS_SRVC_CMD_GET_GRP(a)     (((a) & CONS_SRVC_CMD_GRP_MASK) >> CONS_SRVC_CMD_GRP_BIT)

#define CONS_SRVC_TYPE_GRP_BIT       0x8
#define CONS_SRVC_TYPE_GRP_MASK_     0xF
#define CONS_SRVC_TYPE_GRP_MASK      (CONS_SRVC_TYPE_GRP_MASK_ << CONS_SRVC_TYPE_GRP_BIT)
#define CONS_SRVC_TYPE_SET_GRP(a)    (((a) & CONS_SRVC_TYPE_GRP_MASK_) << CONS_SRVC_TYPE_GRP_BIT)
#define CONS_SRVC_TYPE_GET_GRP(a)    (((a) & CONS_SRVC_TYPE_GRP_MASK) >> CONS_SRVC_TYPE_GRP_BIT)

#define CONS_SRVC_LEN_GRP_BIT        0x0
#define CONS_SRVC_LEN_GRP_MASK_      0xFFF
#define CONS_SRVC_LEN_GRP_MASK       (CONS_SRVC_LEN_GRP_MASK_ << CONS_SRVC_LEN_GRP_BIT)
#define CONS_SRVC_LEN_SET_GRP(a)     (((a) & CONS_SRVC_LEN_GRP_MASK_) << CONS_SRVC_LEN_GRP_BIT)
#define CONS_SRVC_LEN_GET_GRP(a)     (((a) & CONS_SRVC_LEN_GRP_MASK) >> CONS_SRVC_LEN_GRP_BIT)

#define CONS_SRVC_SIG_GRP_BIT        0xC
#define CONS_SRVC_SIG_GRP_MASK_      0x3
#define CONS_SRVC_SIG_GRP_MASK       (CONS_SRVC_SIG_GRP_MASK_ << CONS_SRVC_SIG_GRP_BIT)
#define CONS_SRVC_SIG_SET_GRP(a)     (((a) & CONS_SRVC_SIG_GRP_MASK_) << CONS_SRVC_SIG_GRP_BIT)
#define CONS_SRVC_SIG_GET_GRP(a)     (((a) & CONS_SRVC_SIG_GRP_MASK) >> CONS_SRVC_SIG_GRP_BIT)

typedef uint8_t CONS_RESULT_E_TAG;
typedef enum
{
    CONS_RESULT_SUCCESS = 0x00,
    CONS_RESULT_FAILURE,
    CONS_RESULT_VERIFY_FAILURE,

    CONS_RESULT_MAX
} CONS_RESULT_E;

typedef enum
{
    CONS_HDR_TYPE_CMD = 0x00,
    CONS_HDR_TYPE_MGMT,
    CONS_HDR_TYPE_DATA,
    
    CONS_HDR_TYPE_MAX
} CONS_HDR_TYPE_E;

typedef enum
{
    CONS_SRVC_CMD_GROUP = CONS_SRVC_TYPE_SET_GRP(CONS_HDR_TYPE_CMD),
    // Block
    CONS_SRVC_CMD_BLOCK_NOTI = CONS_SRVC_CMD_GROUP,

#if (P2P_PUBKEY_NOTI == DISABLED)
    // Public Key
    CONS_SRVC_CMD_PUBKEY_NOTI,
#endif // P2P_PUBKEY_NOTI
    CONS_SRVC_MGMT_GROUP = CONS_SRVC_TYPE_SET_GRP(CONS_HDR_TYPE_MGMT),

    CONS_SRVC_DATA_GROUP = CONS_SRVC_TYPE_SET_GRP(CONS_HDR_TYPE_DATA),
    // Transaction
    CONS_SRVC_DATA_TRANSACTION,
    CONS_SRVC_DATA_TRANSACTION_ACK,

    CONS_SRVC_MAX
} CONS_SRVC_E;

typedef enum
{
    CONS_GRP_HDR_SIG_ECDSA = 0x04, // Default
    CONS_GRP_HDR_SIG_ED25519,
    
    CONS_GRP_HDR_SIG_MAX
} CONS_GRP_HDR_SIG_E;

typedef enum
{
    CONS_BLK_GEN_STOP_DISABLED = 0x00,
    CONS_BLK_GEN_STOP_BY_SELF,
    CONS_BLK_GEN_STOP_BY_IS,
    CONS_BLK_GEN_STOP_BY_PEER_DEL,
    
    CONS_BLK_GEN_STOP_MAX
} CONS_BLK_GEN_STOP_E;

//// from cons.h
typedef struct
{
    bool tx_rollback; // Transaction rollback test
} __attribute__((__packed__)) CONS_TEST_T;

typedef struct
{
    bool actived;
    int32_t sockfd;
    struct sockaddr_in sock_addr;
    uint64_t p2p_addr;
    
    char pubkey_dir[CONS_DIR_SIZE];
    char pubkey_path[CONS_PATH_SIZE];
} __attribute__((__packed__)) CONS_PEER_T;

typedef struct
{
    LIST_ITEM_T link;
    uint64_t db_key;
} __attribute__((__packed__)) CONS_TX_REQ_LIST_T;

typedef struct
{
    uint16_t proto_type; // 1 = TCP, 2 = UDP
    uint16_t port;
    uint32_t ip;
    int32_t sockfd;
} __attribute__((__packed__)) CONS_SUBNET_INFO_T;

typedef struct
{
    uint32_t actived;
    uint64_t nn_p2p_addr;
    CONS_SUBNET_INFO_T subnet;
    char nn_pubkey_dir[CONS_DIR_SIZE];
    char nn_pubkey_path[CONS_PATH_SIZE];
} __attribute__((__packed__)) CONS_GEN_INFO_T;

typedef struct
{
    uint32_t total_nn;
    uint32_t my_root_nn_idx;
    uint32_t my_prev_nn_idx;
    uint32_t my_next_nn_idx;
    CONS_GEN_INFO_T root[CONS_NN_MAX];
} __attribute__((__packed__)) CONS_GEN_SEQ_INFO_T;

typedef struct
{
    // blockgen info
    uint32_t blk_gen_round_cnt; // 
    uint32_t blk_gen_interval; // UTC time in milliseconds ( Set only in case of the first NN of rr_net. )
    uint32_t blk_gen_sub_intrvl;
    uint64_t blk_gen_start_time; // In case of genesis block, UTC time in microsecond
    uint64_t blk_gen_start_block;
    //
    uint64_t blk_gen_time; // UTC time in microsecond
    //
    CONS_BLK_GEN_STOP_E blk_gen_stop;

    // rr_net
    CONS_GEN_SEQ_INFO_T nn_gen_seq;

    //
    uint64_t prv_bgt; // UTC time in milliseconds
    uint64_t prv_blk_gen_addr;
    uint8_t prv_blk_hash[HASH_SIZE];
    
    //
    uint64_t prv_blk_num;
    uint64_t blk_num; // block number
} __attribute__((__packed__)) CONS_TIER_T;

typedef struct
{
    uint32_t revision;
    uint32_t tier_num;
    CONS_TIER_T tier[CONS_TIER_MAX];
} __attribute__((__packed__)) CONS_NET_T;


typedef struct
{
    uint64_t nxt_blk_num;
} __attribute__((__packed__)) CONS_BLK_CTRL_T;

typedef struct
{
    uint64_t blk_num;
    uint64_t p2p_addr;
    uint64_t bgt;
    uint8_t pbh[HASH_SIZE];
    uint32_t tx_cnt;
    uint8_t blk_hash[HASH_SIZE];
    uint8_t sig[SIG_SIZE];
    uint8_t sig_pubkey[COMP_PUBKEY_SIZE];
} __attribute__((__packed__)) CONS_LIGHT_BLK_T;

typedef struct
{
    uint64_t db_key;
    uint8_t sc_hash[HASH_SIZE];
} __attribute__((__packed__)) CONS_TX_INFO_T;

typedef struct
{
    uint64_t first_tx_db_key;
    uint64_t last_tx_db_key;
} __attribute__((__packed__)) CONS_DBKEY_INFO_T;

typedef struct
{
    CONS_DBKEY_INFO_T info;
} __attribute__((__packed__)) CONS_DBKEY_T;

typedef struct
{
    uint32_t result;
    uint64_t blk_num;
    uint8_t cnt;
    uint64_t db_key[0];
} __attribute__((__packed__)) CONS_TX_ACK_INFO_T;


typedef struct 
{
    CONS_TEST_T cons_test;
    
    uint32_t peer_cn_num;
    CONS_PEER_T peer[CONS_PEER_MAX]; // 0: NN

    CONS_NET_T net;
    //
    bool b_enc_prikey;
    char prikey_name[CONS_PK_NAME_SIZE];
    char pubkey_name[CONS_PK_NAME_SIZE];
    char key_dir[CONS_DIR_SIZE];
    char my_key_dir[CONS_DIR_SIZE];
    char my_prikey_path[CONS_PATH_SIZE];
    char my_pubkey_path[CONS_PATH_SIZE];
    uint8_t my_comp_pubkey[COMP_PUBKEY_SIZE];
} CONS_CNTX_T;

#ifdef __cplusplus
}
#endif

#endif /* __CONS_TYPES_H__ */

