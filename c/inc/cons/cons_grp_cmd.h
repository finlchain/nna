/**
    @file cons_grp_cmd.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __CONS_GROUP_CMD_H__
#define __CONS_GROUP_CMD_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    uint64_t gen_start_time; // UTC Time in msec
    uint32_t gen_round_cnt;
    uint32_t gen_interval;
    uint64_t first_cn_p2p_addr;
    uint64_t first_blk_num;
} __attribute__((__packed__)) CONS_BLOCK_GEN_SUB_T;

typedef struct
{
    CONS_LIGHT_BLK_T light_blk;
    CONS_DBKEY_T dbkey_list;
} __attribute__((__packed__)) CONS_BLOCK_NOTI_SUB_T;

typedef struct
{
    CONS_GRP_HDR_T grp_hdr;
    CONS_BLOCK_NOTI_SUB_T sub;
} __attribute__((__packed__)) CONS_BLOCK_NOTI_T;

typedef struct
{
    CONS_BLOCK_NOTI_SUB_T sub;
} __attribute__((__packed__)) CONS_BLOCK_NOTI_IND_T;

#if (P2P_PUBKEY_NOTI == DISABLED)
//
typedef struct
{
    uint8_t pubkey[COMP_PUBKEY_SIZE];
} __attribute__((__packed__)) CONS_PUBKEY_NOTI_SUB_T;

typedef struct
{
    CONS_GRP_HDR_T grp_hdr;
    
    CONS_PUBKEY_NOTI_SUB_T sub;
} __attribute__((__packed__)) CONS_PUBKEY_NOTI_T;

typedef struct
{
    CONS_PUBKEY_NOTI_SUB_T sub;
} __attribute__((__packed__)) CONS_PUBKEY_NOTI_IND_T;
#endif  // P2P_PUBKEY_NOTI

// From NN to NN
extern void cons_cmd_block_noti(int32_t sockfd, uint8_t *p_dst_p2p_addr, char *p_pubkey_path, CONS_LIGHT_BLK_T *p_light_blk, CONS_DBKEY_T *p_db_key_list);
extern int32_t cons_cmd_block_noti_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, CONS_SRVC_IND_T *p_cons_ind);

// Local Indication From P2P to CONS
extern void cons_cmd_join_ind (int32_t peer_sockfd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr, P2P_NODE_T *p_node);
extern void cons_cmd_join_cfm (int32_t peer_sockfd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr);

#if (P2P_PUBKEY_NOTI == DISABLED)
extern void cons_cmd_pubkey_noti(int32_t sockfd, uint8_t *p_dst_p2p_addr, char *p_pubkey_path, uint8_t *p_comp_pubkey);
extern int32_t cons_cmd_pubkey_noti_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr,  CONS_SRVC_IND_T *p_cons_ind);
#else
extern int32_t cons_cmd_pubkey_noti_ind (int32_t peer_sockfd, struct sockaddr_in *p_peer_sock_addr, uint64_t peer_p2p_addr, uint8_t *p_pubkey);
#endif // P2P_PUBKEY_NOTI

#ifdef __cplusplus
}
#endif

#endif /* __CONS_GROUP_CMD_H__ */

