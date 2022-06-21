/**
    @file cons_grp.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

// Local
static int32_t cons_pkt_data_grp_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, CONS_SRVC_IND_T *p_cons_ind)
{
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s) type_data(0x%04X) - start\n", __FUNCTION__, p_cons_ind->grp_hdr.type_cmd);

    switch (CONS_SRVC_CMDTYPE_GET_GRP(p_cons_ind->grp_hdr.type_cmd))
    {
    default:
        DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"(%s) unknown service type error\n", __FUNCTION__);
        break;
    }

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s) type_data(0x%04X) - end\n", __FUNCTION__, p_cons_ind->grp_hdr.type_cmd);

    return (ret);
}

static int32_t cons_pkt_cmd_grp_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, CONS_SRVC_IND_T *p_cons_ind)
{
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s) type_cmd(0x%04X) - start\n", __FUNCTION__, p_cons_ind->grp_hdr.type_cmd);

    switch (CONS_SRVC_CMDTYPE_GET_GRP(p_cons_ind->grp_hdr.type_cmd))
    {
    // Block 
    case CONS_SRVC_CMD_BLOCK_NOTI: 
        ret = cons_cmd_block_noti_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_cons_ind);
        break;
 #if (P2P_PUBKEY_NOTI == DISABLED)
    // Public Key
    case CONS_SRVC_CMD_PUBKEY_NOTI:
        ret = cons_cmd_pubkey_noti_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_cons_ind);
        break;
#endif // P2P_PUBKEY_NOTI
    default:
        DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"(%s) unknown service type error\n", __FUNCTION__);
        break;
    }

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s) type_cmd(0x%04X) - end\n", __FUNCTION__, p_cons_ind->grp_hdr.type_cmd);

    return (ret);
}

static int32_t cons_pkt_mgmt_grp_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, CONS_SRVC_IND_T *p_cons_ind)
{
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s) type_mgmt(0x%04X) - start\n", __FUNCTION__, p_cons_ind->grp_hdr.type_cmd);

    switch (CONS_SRVC_CMDTYPE_GET_GRP(p_cons_ind->grp_hdr.type_cmd))
    {
    default:
        DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"(%s) unknown service type error\n", __FUNCTION__);
        break;
    }

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s) type_mgmt(0x%04X) - end\n", __FUNCTION__, p_cons_ind->grp_hdr.type_cmd);

    return (ret);
}

int32_t cons_pkt_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, CONS_SRVC_IND_T *p_cons_ind)
{
    int32_t ret = ERROR_;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    MEMCPY_REV2(&p_cons_ind->grp_hdr.type_cmd, BYTE_2);
    MEMCPY_REV2(&p_cons_ind->grp_hdr.len_sig, BYTE_2);

    switch (p_cons_ind->grp_hdr.type_cmd & CONS_SRVC_TYPE_GRP_MASK)
    {
    case CONS_SRVC_DATA_GROUP:
        ret = cons_pkt_data_grp_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_cons_ind);
        break;
    case CONS_SRVC_CMD_GROUP:
        ret = cons_pkt_cmd_grp_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_cons_ind);
        break;
    case CONS_SRVC_MGMT_GROUP:
        ret = cons_pkt_mgmt_grp_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_cons_ind);
        break;
    default:
        DBG_PRINT(DBG_CONS, DBG_ERROR, (void *)"(%s) unknown type error\n", __FUNCTION__);
        break;
    }

    return (ret);
}

int32_t cons_peer_del_ind(int32_t sockfd)
{
    int32_t ret;

    cons_rr_set_blk_gen_stop(CONS_BLK_GEN_STOP_BY_PEER_DEL);

    // Subnet based setting
    ret = cons_peer_del_nn(sockfd);
    if (ret == SUCCESS_)
    {
        return (ret);
    }

    // Setting between NNs
    ret = cons_clr_nxt_nn(sockfd, NULL, P2P_NULL_ADDR);
    if (ret == SUCCESS_)
    {
        return (ret);
    }

    //ASSERT_M(ret == SUCCESS_);

    return (ret);
}

