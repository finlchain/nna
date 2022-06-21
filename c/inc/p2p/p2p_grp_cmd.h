/**
    @file p2p_grp_cmd.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __P2P_GROUP_CMD_H__
#define __P2P_GROUP_CMD_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define P2P_LEAVE_REASON_BY_MYSELF 1

//
typedef struct
{
    uint64_t joining_addr;
    P2P_NODE_INFO_T node_info;
} __attribute__((__packed__)) P2P_JOIN_REQ_SUB_T;

typedef struct
{
    P2P_COM_HDR_T com_hdr;
    
    P2P_JOIN_REQ_SUB_T sub;
} __attribute__((__packed__)) P2P_JOIN_REQ_T;

typedef struct
{
    P2P_GRP_TLV_HDR_T tlv_hdr;
    
    P2P_JOIN_REQ_SUB_T sub;
} __attribute__((__packed__)) P2P_JOIN_IND_T;

//
typedef struct
{
    uint64_t allocated_addr;
    P2P_NODE_INFO_T node_info;
} __attribute__((__packed__)) P2P_JOIN_RESP_SUB_T;

typedef struct
{
    P2P_COM_HDR_T com_hdr;
    
    P2P_JOIN_RESP_SUB_T sub;
} __attribute__((__packed__)) P2P_JOIN_RESP_T;

typedef struct
{
    P2P_GRP_TLV_HDR_T tlv_hdr;
    
    P2P_JOIN_RESP_SUB_T sub;
} __attribute__((__packed__)) P2P_JOIN_CFM_T;

#if (P2P_PUBKEY_NOTI == ENABLED)
//
typedef struct
{
    uint8_t pubkey[COMP_PUBKEY_SIZE];
} __attribute__((__packed__)) P2P_PUBKEY_NOTI_SUB_T;

typedef struct
{
    P2P_COM_HDR_T com_hdr;
    
    P2P_PUBKEY_NOTI_SUB_T sub;
} __attribute__((__packed__)) P2P_PUBKEY_NOTI_T;

typedef struct
{
    P2P_GRP_TLV_HDR_T tlv_hdr;
    
    P2P_PUBKEY_NOTI_SUB_T sub;
} __attribute__((__packed__)) P2P_PUBKEY_NOTI_IND_T;
#endif // P2P_PUBKEY_NOTI

//
typedef struct
{
    uint64_t requested_addr;
    uint8_t requested_reason;
} __attribute__((__packed__)) P2P_LEAVE_REQ_SUB_T;

typedef struct
{
    P2P_COM_HDR_T com_hdr;
    
    P2P_LEAVE_REQ_SUB_T sub;
} __attribute__((__packed__)) P2P_LEAVE_REQ_T;

typedef struct
{
    P2P_GRP_TLV_HDR_T tlv_hdr;
    
    P2P_LEAVE_REQ_SUB_T sub;
} __attribute__((__packed__)) P2P_LEAVE_IND_T;

//
typedef struct
{
    uint64_t leaving_addr;
    uint8_t leaving_reason;
} __attribute__((__packed__)) P2P_LEAVE_NOTI_SUB_T;

typedef struct
{
    P2P_COM_HDR_T com_hdr;
    
    P2P_LEAVE_NOTI_SUB_T sub;
} __attribute__((__packed__)) P2P_LEAVE_NOTI_T;

typedef struct
{
    P2P_GRP_TLV_HDR_T tlv_hdr;
    
    P2P_LEAVE_NOTI_SUB_T sub;
} __attribute__((__packed__)) P2P_LEAVE_NOTI_IND_T;

// 
extern int32_t p2p_cmd_join_req (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_NODE_T *p_node);
extern int32_t p2p_cmd_join_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr);

// 
extern int32_t p2p_cmd_join_resp (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr);
extern int32_t p2p_cmd_join_cfm (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr);

#if (P2P_PUBKEY_NOTI == ENABLED)
//
extern int32_t p2p_cmd_pubkey_noti (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, uint8_t *p_comp_pubkey);
extern int32_t p2p_cmd_pubkey_noti_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr);
#endif // P2P_PUBKEY_NOTI

#ifdef __cplusplus
}
#endif

#endif /* __P2P_GROUP_CMD_H__ */

