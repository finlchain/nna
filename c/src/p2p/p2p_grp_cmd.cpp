/**
    @file p2p_grp_cmd.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

// 
int32_t p2p_cmd_join_req (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_NODE_T *p_node)
{
    int32_t ret = ERROR_;
    P2P_JOIN_REQ_T *p_join_req;
    uint32_t buf_len = sizeof(P2P_JOIN_REQ_T);
    uint32_t sub_len = sizeof(P2P_JOIN_REQ_SUB_T);
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    uint32_t p2p_info;

    DBG_PRINT (DBG_P2P, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"sockfd(%d) buf_len(%d)\n", sockfd, buf_len);

    p2p_info = P2P_GRP_HDR_SET_CRC(P2P_GRP_HDR_CRC);
    p2p_info |= P2P_GRP_HDR_SET_ENC(P2P_GRP_HDR_ENC_DISABLED);

    p_join_req = (P2P_JOIN_REQ_T *)MALLOC_M(buf_len+UTIL_CRC_LEN);
    ASSERT_M(p_join_req);

    // Set Group Header
    // Destination Address
    MEMCPY_REV(&p_join_req->com_hdr.grp_hdr.dst_addr, &p_grp_hdr->dst_addr, P2P_ADDR_LEN);
    // Source Address
    MEMCPY_REV(&p_join_req->com_hdr.grp_hdr.src_addr, &p_p2p_cntx->my_p2p_addr.u64, P2P_ADDR_LEN);
    // Timestamp
    p_join_req->com_hdr.grp_hdr.timestamp = util_curtime_ms();
    MEMCPY_REV2(&p_join_req->com_hdr.grp_hdr.timestamp, P2P_TIMESTAMP_LEN);
    // Information
    MEMCPY_REV(&p_join_req->com_hdr.grp_hdr.info, &p2p_info, BYTE_4);
    // Sequence Number
    MEMCPY_REV(&p_join_req->com_hdr.grp_hdr.seq_num, &p_p2p_cntx->my_p2p_cmd_sn, BYTE_2);
    p_p2p_cntx->my_p2p_cmd_sn++;
    // Length
    p_join_req->com_hdr.grp_hdr.len = sizeof(P2P_GRP_TLV_HDR_T)+sub_len;
    MEMCPY_REV2(&p_join_req->com_hdr.grp_hdr.len, BYTE_2);

    // Set TLV Header
    p_join_req->com_hdr.tlv_hdr.tlv = 0;
    p_join_req->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_NEXT(0);
    p_join_req->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_TYPE_CMD(P2P_SRVC_CMD_JOIN_REQ);
    p_join_req->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_LEN(sub_len);
    MEMCPY_REV2(&p_join_req->com_hdr.tlv_hdr.tlv, BYTE_4);

    // Set Sub
    MEMCPY_REV(&p_join_req->sub.joining_addr, &p_p2p_cntx->my_p2p_addr.u64, P2P_ADDR_LEN);
    
    MEMSET_M(&p_join_req->sub.node_info, 0x00, sizeof(P2P_NODE_INFO_T));
    //p_join_req->sub.node_info.mac_addr = 0;
    p_join_req->sub.node_info.ip4_addr = 0;
    MEMCPY_REV(&p_join_req->sub.node_info.p2p_addr, &p_p2p_cntx->my_p2p_addr.u64, P2P_ADDR_LEN);
    p_join_req->sub.node_info.node.node_type = p_node->node_type;
    p_join_req->sub.node_info.node.node_rule = p_node->node_rule;

    // CRC32
    if (P2P_GRP_HDR_GET_CRC(p2p_info))
    {
        util_cal_crc32((uint8_t *)p_join_req, buf_len);
        
        buf_len += UTIL_CRC_LEN;
    }

    DBG_DUMP(DBG_APP_TX, DBG_NONE, (void *)"join_req", (uint8_t *)p_join_req, buf_len);
    
    ret = sock_send_data(sockfd, p_peer_sock_addr, (uint8_t *)p_join_req, buf_len);

    FREE_M(p_join_req);

    return (ret);
}

int32_t p2p_cmd_join_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr)
{
    P2P_JOIN_IND_T *p_join_ind = (P2P_JOIN_IND_T *)p_sub_hdr;
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    uint64_t joining_addr = P2P_NULL_ADDR;

    DBG_PRINT (DBG_P2P, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    //
    DBG_PRINT (DBG_P2P, DBG_NONE, (void *)"p_grp_hdr->dst_addr(0x%016llX)\n", p_grp_hdr->dst_addr);
    DBG_PRINT (DBG_P2P, DBG_NONE, (void *)"p_grp_hdr->src_addr(0x%016llX)\n", p_grp_hdr->src_addr);
    DBG_PRINT (DBG_P2P, DBG_NONE, (void *)"p_grp_hdr->timestamp(0x%016llX)\n", p_grp_hdr->timestamp);
    DBG_PRINT (DBG_P2P, DBG_NONE, (void *)"p_grp_hdr->info(0x%08X)\n", p_grp_hdr->info);
    DBG_PRINT (DBG_P2P, DBG_NONE, (void *)"p_grp_hdr->seq_num(0x%08X)\n", p_grp_hdr->seq_num);
    DBG_PRINT (DBG_P2P, DBG_NONE, (void *)"p_grp_hdr->len(0x%08X)\n", p_grp_hdr->len);

    //
    MEMCPY_REV2(&p_join_ind->sub.joining_addr, P2P_ADDR_LEN);

    MEMCPY_REV2(&p_join_ind->sub.node_info.mac_addr, MAC_ADDR_LEN);
    MEMCPY_REV2(&p_join_ind->sub.node_info.ip4_addr, BYTE_4);
    MEMCPY_REV2(&p_join_ind->sub.node_info.p2p_addr, P2P_ADDR_LEN);

    if (!(p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN))
    {
        DBG_PRINT (DBG_P2P, DBG_ERROR, (void *)"Error - my_node_info.node_rule(%d)\n", p_p2p_cntx->my_node_info.node_rule);
        joining_addr = P2P_NULL_ADDR;
    }
    else if (p_grp_hdr->dst_addr != p_p2p_cntx->my_p2p_addr.u64)
    {
        // From my subnet to me.
        if (IS_MY_SUBNET_ADDR(p_grp_hdr->src_addr, p_p2p_cntx->my_cluster_root))
        {
            DBG_PRINT (DBG_P2P, DBG_ERROR, (void *)"Error - dst_addr(0x%016llX) my_p2p_addr(0x%016llX)\n", p_grp_hdr->dst_addr, p_p2p_cntx->my_p2p_addr.u64);
        }

        joining_addr = P2P_NULL_ADDR;
    }
    else
    {
        if (p_join_ind->sub.joining_addr == P2P_NULL_ADDR)
        {
            ASSERT_M(0);
        }
        else
        {
            joining_addr = p_join_ind->sub.joining_addr;

            if ((joining_addr & P2P_SUBNET_ADDR_MASK) != p_p2p_cntx->my_p2p_addr.u64)
            {
                DBG_PRINT (DBG_P2P, DBG_ERROR, (void *)"Error - joining_addr(0x%016llX) my_p2p_addr(0x%016llX)\n", joining_addr, p_p2p_cntx->my_p2p_addr.u64);
                joining_addr = P2P_NULL_ADDR;
            }
        }
    }

    if (AUTO_TX_ON_RX_SIDE)
    {
        P2P_GRP_HDR_T grp_hdr;
        P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

        MEMCPY_M (&grp_hdr.dst_addr, &joining_addr, sizeof (grp_hdr.dst_addr));
        MEMCPY_M (&grp_hdr.src_addr, &p_p2p_cntx->my_p2p_addr.u64, P2P_ADDR_LEN); // My Address....

        p2p_cmd_join_resp(rx_sockfd, p_peer_sock_addr, &grp_hdr);
    }
    else
    {
        // Sent it to Tx thread...
    }

    // 
    cons_cmd_join_ind(rx_sockfd, p_peer_sock_addr, joining_addr, &p_join_ind->sub.node_info.node);
    
    return (SUCCESS_);
}

// 
int32_t p2p_cmd_join_resp (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr)
{
    int32_t ret = ERROR_;
    P2P_JOIN_RESP_T *p_join_resp;
    uint32_t buf_len = sizeof(P2P_JOIN_RESP_T);
    uint32_t sub_len = sizeof(P2P_JOIN_RESP_SUB_T);
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    uint32_t p2p_info;

    DBG_PRINT (DBG_P2P, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"sockfd(%d) buf_len(%d)\n", sockfd, buf_len);
    
    //
    p2p_info = P2P_GRP_HDR_SET_CRC(P2P_GRP_HDR_CRC);
    p2p_info |= P2P_GRP_HDR_SET_ENC(P2P_GRP_HDR_ENC_DISABLED);

    p_join_resp = (P2P_JOIN_RESP_T *)MALLOC_M(buf_len+UTIL_CRC_LEN);
    ASSERT_M(p_join_resp);

    // Set Group Header
    // Destination Address
    MEMCPY_REV(&p_join_resp->com_hdr.grp_hdr.dst_addr, &p_grp_hdr->dst_addr, P2P_ADDR_LEN);
    // Source Address
    MEMCPY_REV(&p_join_resp->com_hdr.grp_hdr.src_addr, &p_p2p_cntx->my_p2p_addr.u64, P2P_ADDR_LEN);
    // Timestamp
    p_join_resp->com_hdr.grp_hdr.timestamp = util_curtime_ms();
    MEMCPY_REV2(&p_join_resp->com_hdr.grp_hdr.timestamp, P2P_TIMESTAMP_LEN);
    // Information
    MEMCPY_REV(&p_join_resp->com_hdr.grp_hdr.info, &p2p_info, BYTE_4);
    // Sequence Number
    MEMCPY_REV(&p_join_resp->com_hdr.grp_hdr.seq_num, &p_p2p_cntx->my_p2p_cmd_sn, BYTE_2);
    p_p2p_cntx->my_p2p_cmd_sn++;
    // Length
    p_join_resp->com_hdr.grp_hdr.len = sizeof(P2P_GRP_TLV_HDR_T)+sub_len;
    MEMCPY_REV2(&p_join_resp->com_hdr.grp_hdr.len, BYTE_2);

    // Set TLV Header
    p_join_resp->com_hdr.tlv_hdr.tlv = 0;
    p_join_resp->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_NEXT(0);
    p_join_resp->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_TYPE_CMD(P2P_SRVC_CMD_JOIN_RESP);
    p_join_resp->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_LEN(sub_len);
    MEMCPY_REV2(&p_join_resp->com_hdr.tlv_hdr.tlv, BYTE_4);

    // Set Sub
    MEMCPY_REV(&p_join_resp->sub.allocated_addr, &p_grp_hdr->dst_addr, P2P_ADDR_LEN);

    MEMSET_M(&p_join_resp->sub.node_info, 0x00, sizeof(P2P_NODE_INFO_T));
    
    // CRC32
    if (P2P_GRP_HDR_GET_CRC(p2p_info))
    {
        util_cal_crc32((uint8_t *)p_join_resp, buf_len);
        
        buf_len += UTIL_CRC_LEN;
    }

    DBG_DUMP(DBG_APP_TX, DBG_NONE, (void *)"join_resp", (uint8_t *)p_join_resp, buf_len);
    
    ret = sock_send_data(sockfd, p_peer_sock_addr, (uint8_t *)p_join_resp, buf_len);

    FREE_M(p_join_resp);

    return (ret);
}

int32_t p2p_cmd_join_cfm (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr)
{
    P2P_JOIN_CFM_T *p_join_cfm = (P2P_JOIN_CFM_T *)p_sub_hdr;
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    uint64_t allocated_addr = P2P_NULL_ADDR;

    DBG_PRINT (DBG_P2P, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    //
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->dst_addr(0x%016llX)\n", p_grp_hdr->dst_addr);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->src_addr(0x%016llX)\n", p_grp_hdr->src_addr);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->timestamp(0x%016llX)\n", p_grp_hdr->timestamp);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->info(0x%08X)\n", p_grp_hdr->info);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->seq_num(0x%08X)\n", p_grp_hdr->seq_num);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->len(0x%08X)\n", p_grp_hdr->len);

    //
    MEMCPY_REV2(&p_join_cfm->sub.allocated_addr, P2P_ADDR_LEN);

    MEMCPY_REV2(&p_join_cfm->sub.node_info.mac_addr, MAC_ADDR_LEN);
    MEMCPY_REV2(&p_join_cfm->sub.node_info.ip4_addr, BYTE_4);
    MEMCPY_REV2(&p_join_cfm->sub.node_info.p2p_addr, P2P_ADDR_LEN);

    if (p_join_cfm->sub.allocated_addr == P2P_NULL_ADDR)
    {
        if (IS_MY_SUBNET_ADDR(p_grp_hdr->src_addr, p_p2p_cntx->my_cluster_root))
        {
            DBG_PRINT (DBG_P2P, DBG_ERROR, (void *)"Error - allocated_addr from src address(0x%016llX)\n", p_grp_hdr->src_addr);
            //ASSERT_M(0);
            return (ERROR_);
        }
    }
    else
    {
        allocated_addr = p_join_cfm->sub.allocated_addr;
    }

    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"allocated_addr (0x%016llX)\n", allocated_addr);

    // 
    cons_cmd_join_cfm(rx_sockfd, p_peer_sock_addr, p_grp_hdr->src_addr);
    
    return (SUCCESS_);
}


#if (P2P_PUBKEY_NOTI == ENABLED)
//
int32_t p2p_cmd_pubkey_noti (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, uint8_t *p_comp_pubkey)
{
    int32_t ret = ERROR_;
    P2P_PUBKEY_NOTI_T *p_pubkey_noti;
    uint32_t buf_len = sizeof(P2P_PUBKEY_NOTI_T);
    uint32_t sub_len = sizeof(P2P_PUBKEY_NOTI_SUB_T);
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    uint32_t p2p_info;

    DBG_PRINT (DBG_P2P, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"sockfd(%d) buf_len(%d)\n", sockfd, buf_len);

    //
    p2p_info = P2P_GRP_HDR_SET_CRC(P2P_GRP_HDR_CRC);
    p2p_info |= P2P_GRP_HDR_SET_ENC(P2P_GRP_HDR_ENC_DISABLED);

    p_pubkey_noti = (P2P_PUBKEY_NOTI_T *)MALLOC_M(buf_len+UTIL_CRC_LEN);
    ASSERT_M(p_pubkey_noti);

    // Set Group Header
    // Destination Address
    MEMCPY_REV(&p_pubkey_noti->com_hdr.grp_hdr.dst_addr, &p_grp_hdr->dst_addr, P2P_ADDR_LEN);
    // Source Address
    MEMCPY_REV(&p_pubkey_noti->com_hdr.grp_hdr.src_addr, &p_p2p_cntx->my_p2p_addr.u64, P2P_ADDR_LEN);
    // Timestamp
    p_pubkey_noti->com_hdr.grp_hdr.timestamp = util_curtime_ms();
    MEMCPY_REV2(&p_pubkey_noti->com_hdr.grp_hdr.timestamp, P2P_TIMESTAMP_LEN);
    // Information
    MEMCPY_REV(&p_pubkey_noti->com_hdr.grp_hdr.info, &p2p_info, BYTE_4);
    // Sequence Number
    MEMCPY_REV(&p_pubkey_noti->com_hdr.grp_hdr.seq_num, &p_p2p_cntx->my_p2p_cmd_sn, BYTE_2);
    p_p2p_cntx->my_p2p_cmd_sn++;
    // Length
    p_pubkey_noti->com_hdr.grp_hdr.len = sizeof(P2P_GRP_TLV_HDR_T)+sub_len;
    MEMCPY_REV2(&p_pubkey_noti->com_hdr.grp_hdr.len, BYTE_2);

    // Set TLV Header
    p_pubkey_noti->com_hdr.tlv_hdr.tlv = 0;
    p_pubkey_noti->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_NEXT(0);
    p_pubkey_noti->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_TYPE_CMD(P2P_SRVC_CMD_PUBKEY_NOTI);
    p_pubkey_noti->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_LEN(sub_len);
    MEMCPY_REV2(&p_pubkey_noti->com_hdr.tlv_hdr.tlv, BYTE_4);

    // Set Sub
    MEMCPY_REV(p_pubkey_noti->sub.pubkey, p_comp_pubkey, COMP_PUBKEY_SIZE);
    DBG_DUMP(DBG_P2P, DBG_NONE, (void *)"snd_pubkey", (uint8_t *)p_pubkey_noti->sub.pubkey, COMP_PUBKEY_SIZE);

    // CRC32
    if (P2P_GRP_HDR_GET_CRC(p2p_info))
    {
        util_cal_crc32((uint8_t *)p_pubkey_noti, buf_len);
        
        buf_len += UTIL_CRC_LEN;
    }

    DBG_DUMP(DBG_APP_TX, DBG_NONE, (void *)"pubkey_noti", (uint8_t *)p_pubkey_noti, buf_len);
    
    ret = sock_send_data(sockfd, p_peer_sock_addr, (uint8_t *)p_pubkey_noti, buf_len);

    FREE_M(p_pubkey_noti);

    return (ret);
}

int32_t p2p_cmd_pubkey_noti_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr)
{
    P2P_PUBKEY_NOTI_IND_T *p_pubkey_noti_ind = (P2P_PUBKEY_NOTI_IND_T *)p_sub_hdr;
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    DBG_PRINT (DBG_P2P, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    //
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->dst_addr(0x%016llX)\n", p_grp_hdr->dst_addr);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->src_addr(0x%016llX)\n", p_grp_hdr->src_addr);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->timestamp(0x%016llX)\n", p_grp_hdr->timestamp);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->info(0x%08X)\n", p_grp_hdr->info);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->seq_num(0x%08X)\n", p_grp_hdr->seq_num);
    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"p_grp_hdr->len(0x%08X)\n", p_grp_hdr->len);
    
    //
    MEMCPY_REV2(p_pubkey_noti_ind->sub.pubkey, COMP_PUBKEY_SIZE);
    DBG_DUMP(DBG_P2P, DBG_NONE, (void *)"rcv_pubkey", (uint8_t *)p_pubkey_noti_ind->sub.pubkey, COMP_PUBKEY_SIZE);

    DBG_PRINT (DBG_P2P, DBG_INFO, (void *)"MY P2P Addr(0x%016llX) / Dst P2P Addr(0x%016llX)\n", p_p2p_cntx->my_p2p_addr.u64, p_grp_hdr->dst_addr);

    if (p_grp_hdr->dst_addr == p_p2p_cntx->my_p2p_addr.u64)
    {
        // 
        cons_cmd_pubkey_noti_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr->src_addr, p_pubkey_noti_ind->sub.pubkey);
    }
    
    return (SUCCESS_);
}
#endif // P2P_PUBKEY_NOTI

