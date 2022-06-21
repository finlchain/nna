/**
    @file cons_grp.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/


#ifndef __CONS_GRP_H__
#define __CONS_GRP_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    uint8_t r[SIG_R_SIZE];
    uint8_t s[SIG_S_SIZE];
} __attribute__((__packed__)) CONS_SIG_T;

typedef struct
{
    uint16_t type_cmd;
    uint16_t len_sig;
} __attribute__((__packed__)) CONS_GRP_HDR_T;

typedef struct
{
    uint64_t blk_num;
    uint8_t blk_hash[HASH_SIZE];
    CONS_SIG_T sig;
} __attribute__((__packed__)) CONS_HDR_T;

////
typedef struct
{
    CONS_GRP_HDR_T grp_hdr;
    
    uint8_t buf[0];
} __attribute__((__packed__)) CONS_SRVC_REQ_T;

typedef struct
{
    CONS_GRP_HDR_T grp_hdr;
    
    uint8_t buf[0];
} __attribute__((__packed__)) CONS_SRVC_CFM_T;

typedef struct
{
    CONS_GRP_HDR_T grp_hdr;
    
    uint8_t buf[0];
} __attribute__((__packed__)) CONS_SRVC_IND_T;

extern int32_t cons_pkt_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, CONS_SRVC_IND_T *p_cons_ind);
extern int32_t cons_peer_del_ind(int32_t sockfd);

#ifdef __cplusplus
}
#endif

#endif /* __CONS_GRP_H__ */

