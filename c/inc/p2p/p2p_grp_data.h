/**
    @file p2p_grp_data.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __P2P_GRP_DATA_H__
#define __P2P_GRP_DATA_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    P2P_COM_HDR_T com_hdr;

    uint8_t data[0];
} __attribute__((__packed__)) P2P_DATA_REQ_T;

typedef struct
{
    P2P_GRP_TLV_HDR_T tlv_hdr;

    uint8_t data[0];
} __attribute__((__packed__)) P2P_DATA_IND_T;

typedef struct
{
    uint32_t result;
} __attribute__((__packed__)) P2P_DATA_CFM_SUB_T;

typedef struct
{
    P2P_COM_HDR_T com_hdr;
    
    P2P_DATA_CFM_SUB_T sub;
} __attribute__((__packed__)) P2P_DATA_CFM_T;

typedef struct
{
    P2P_GRP_TLV_HDR_T tlv_hdr;
    
    P2P_DATA_CFM_SUB_T sub;
} __attribute__((__packed__)) P2P_DATA_CFM_IND_T;

extern int32_t p2p_data_req (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, const char *p_pubkey_path, uint8_t *p_data, uint32_t data_len, uint8_t *p_dst_addr);
extern int32_t p2p_data_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr);
extern int32_t p2p_data_cfm (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, uint32_t result, uint8_t *p_dst_addr);
extern int32_t p2p_data_cfm_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr);

#ifdef __cplusplus
}
#endif

#endif /* __P2P_GRP_DATA_H__ */

