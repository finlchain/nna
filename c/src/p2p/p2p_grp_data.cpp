/**
    @file p2p_grp_data.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

int32_t p2p_data_req (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, const char *p_pubkey_path, uint8_t *p_data, uint32_t data_len, uint8_t *p_dst_addr)
{
    int32_t ret = ERROR_;
    P2P_DATA_REQ_T *p_data_req;
    uint32_t buf_len = sizeof(P2P_DATA_REQ_T)+data_len;
    uint32_t p2p_info;

    DBG_PRINT (DBG_P2P, DBG_NONE, (void *)"(%s) sockfd(%d) len(%d)\n", __FUNCTION__, sockfd, data_len);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    p_data_req = (P2P_DATA_REQ_T *) MALLOC_M(buf_len+UTIL_CRC_LEN);
    if (p_data_req)
    {
        uint16_t len = 0;
        P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
        
        // Set TLV Header
        p_data_req->com_hdr.tlv_hdr.tlv = 0;
        p_data_req->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_NEXT(0);
        p_data_req->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_TYPE_CMD(P2P_SRVC_DATA_REQ);
        ASSERT_M (data_len <= P2P_LEN_MAX);
        p_data_req->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_LEN(data_len);
        MEMCPY_REV2(&p_data_req->com_hdr.tlv_hdr.tlv, BYTE_4);

        // Set Data
        MEMCPY_M(p_data_req->data, p_data, data_len);

        //
        len += sizeof(P2P_GRP_TLV_HDR_T);
        len += data_len;

        // Set Group Header 1
        // Destination Address
        MEMCPY_REV(&p_data_req->com_hdr.grp_hdr.dst_addr, p_dst_addr, P2P_ADDR_LEN);
        // Source Address
        MEMCPY_REV(&p_data_req->com_hdr.grp_hdr.src_addr, &p_p2p_cntx->my_p2p_addr.u64, P2P_ADDR_LEN);

        p_data_req->com_hdr.grp_hdr.info = P2P_GRP_HDR_SET_CRC(P2P_GRP_HDR_CRC);
        if(p_pubkey_path)
        {
            p_data_req->com_hdr.grp_hdr.info |= P2P_GRP_HDR_SET_ENC(P2P_DEFAULT_ENC);
        }
        p_data_req->com_hdr.grp_hdr.info |= P2P_GRP_HDR_SET_VER(P2P_VERSION);

        p2p_info = p_data_req->com_hdr.grp_hdr.info;

        // Encryption
        switch (P2P_GRP_HDR_GET_ENC(p2p_info))
        {
        case P2P_GRP_HDR_ENC_ECIES:
        {
            uint8_t *p_msg, *p_enc_msg;
            uint32_t enc_msg_len;

            enc_msg_len = CEIL(len, AES_BLOCK_SIZE)+OPENSSL_ECIES_R_LEN+OPENSSL_ECIES_MAC_LEN;
            if (!IS_REMAINDER(len, AES_BLOCK_SIZE))
            {
                enc_msg_len += AES_BLOCK_SIZE;
            }

            p_msg = (uint8_t *)MALLOC_M(P2P_GRP_HDR_LEN + enc_msg_len);
            p_enc_msg = &p_msg[P2P_GRP_HDR_LEN];

            DBG_DUMP(DBG_P2P, DBG_NONE, (void *)"p_plaintext", (uint8_t *)&p_data_req->com_hdr.tlv_hdr, len);
            DBG_PRINT (DBG_P2P, DBG_NONE, (void *)"p_pubkey_path (%s)\n", p_pubkey_path);
            
            ret = p2p_ecies_encrypt(p_pubkey_path, NULL, 0, NULL, 0, 
                            (uint8_t *)&p_data_req->com_hdr.tlv_hdr, len, 
                            (uint8_t **) &(p_enc_msg), &enc_msg_len);
            
            if (ret == SUCCESS_)
            {
                DBG_DUMP(DBG_P2P, DBG_NONE, (void *)"p_enc_msg", (uint8_t *)p_enc_msg, enc_msg_len);
                
                MEMCPY_M(p_msg, &p_data_req->com_hdr.grp_hdr, P2P_GRP_HDR_LEN);
                
                FREE_M(p_data_req);
                p_data_req = (P2P_DATA_REQ_T *)p_msg;

                len = enc_msg_len;
                
                buf_len = P2P_GRP_HDR_LEN + enc_msg_len;
            }
            else
            {
                DBG_PRINT (DBG_P2P, DBG_ERROR, (void *)"p2p_ecies_encrypt Error\n");
                buf_len = 0;
            }
            break;
        }
        default :
            break;
        }

        //
        if (buf_len)
        {
            // Set Group Header 2
            // Timestamp
            p_data_req->com_hdr.grp_hdr.timestamp = util_curtime_ms();
            MEMCPY_REV2(&p_data_req->com_hdr.grp_hdr.timestamp, P2P_TIMESTAMP_LEN);
            // Information
            MEMCPY_REV2(&p_data_req->com_hdr.grp_hdr.info, BYTE_4);
            // Sequence Number
            MEMCPY_REV(&p_data_req->com_hdr.grp_hdr.seq_num, &p_p2p_cntx->my_p2p_data_sn, BYTE_2);
            p_p2p_cntx->my_p2p_data_sn++;
            // Length
            MEMCPY_REV(&p_data_req->com_hdr.grp_hdr.len, &len, BYTE_2);

            // CRC32
            if (P2P_GRP_HDR_GET_CRC(p2p_info))
            {
                util_cal_crc32((uint8_t *)p_data_req, buf_len);
                
                buf_len += UTIL_CRC_LEN;
            }
            
            DBG_DUMP(DBG_P2P, DBG_NONE, (void *)"data_req", (uint8_t *)p_data_req, buf_len);

            ret = sock_send_data(sockfd, p_peer_sock_addr, (uint8_t *)p_data_req, buf_len);
        }
        else
        {
            ASSERT_M(0);
        }
        
        FREE_M (p_data_req);
    }
    get_current_rss_monitor(DBG_NONE, (char *)"2");

    return (ret);
}

int32_t p2p_data_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr)
{
    P2P_DATA_IND_T *p_data_ind = (P2P_DATA_IND_T *)p_sub_hdr;
    uint32_t data_len = (p_data_ind->tlv_hdr.tlv & P2P_TLV_HDR_LEN_MASK) >> P2P_TLV_HDR_LEN_BIT;

    DBG_PRINT(DBG_P2P, DBG_NONE, (void *)"Data Length = %d\n", data_len);
    DBG_DUMP(DBG_P2P, DBG_NONE, (void *)"Data", p_data_ind->data, data_len);

#if (P2P_DATA_IND_UP_LAYER == ENABLED)
    cons_pkt_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, (CONS_SRVC_IND_T *)p_sub_hdr->buf);
#else
    if (AUTO_TX_ON_RX_SIDE)
    {
        p2p_data_cfm(rx_sockfd, p_peer_sock_addr, P2P_RESULT_SUCCESS, &p_grp_hdr->src_addr);
    }
    else
    {
        // Sent it to Tx thread...
    }
#endif // P2P_DATA_IND_UP_LAYER
    
    return SUCCESS_;
}

int32_t p2p_data_cfm (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, uint32_t result, uint8_t *p_dst_addr)
{
    int32_t ret = ERROR_;
    P2P_DATA_CFM_T *p_data_cfm;
    uint32_t buf_len = sizeof(P2P_DATA_CFM_T);
    uint32_t sub_len = sizeof(P2P_DATA_CFM_SUB_T);
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    uint32_t p2p_info;
    
    uint16_t len = 0;
    
    DBG_PRINT (DBG_P2P, DBG_TRACE, (void *)"(%s) sockfd(%d)\n", __FUNCTION__, sockfd);
    
    p_data_cfm = (P2P_DATA_CFM_T *)MALLOC_M(buf_len+UTIL_CRC_LEN);
    ASSERT_M(p_data_cfm);
    
    // Set TLV Header
    p_data_cfm->com_hdr.tlv_hdr.tlv = 0;
    p_data_cfm->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_NEXT(0);
    p_data_cfm->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_TYPE_CMD(P2P_SRVC_DATA_CFM);
    p_data_cfm->com_hdr.tlv_hdr.tlv |= P2P_TLV_HDR_SET_LEN(sub_len);
    MEMCPY_REV2(&p_data_cfm->com_hdr.tlv_hdr.tlv, BYTE_4);
    
    // Set Data
    MEMCPY_REV(&p_data_cfm->sub.result, &result, BYTE_4);
    
    //
    len += sizeof(P2P_GRP_TLV_HDR_T);
    len += sizeof(sub_len);

    //
    // Destination Address
    MEMCPY_REV(&p_data_cfm->com_hdr.grp_hdr.dst_addr, &p_dst_addr, P2P_ADDR_LEN);
    // Source Address
    MEMCPY_REV(&p_data_cfm->com_hdr.grp_hdr.src_addr, &p_p2p_cntx->my_p2p_addr.u64, P2P_ADDR_LEN);
    // Timestamp
    p_data_cfm->com_hdr.grp_hdr.timestamp = util_curtime_ms();
    MEMCPY_REV2(&p_data_cfm->com_hdr.grp_hdr.timestamp, P2P_TIMESTAMP_LEN);
    // Information
    p2p_info = P2P_GRP_HDR_SET_CRC(P2P_GRP_HDR_CRC);
    p2p_info |= P2P_GRP_HDR_SET_ENC(P2P_DEFAULT_ENC);
    p2p_info |= P2P_GRP_HDR_SET_VER(P2P_VERSION);
    MEMCPY_REV(&p_data_cfm->com_hdr.grp_hdr.info, &p2p_info, BYTE_4);
    // Sequence Number
    MEMCPY_REV(&p_data_cfm->com_hdr.grp_hdr.seq_num, &p_p2p_cntx->my_p2p_data_sn, BYTE_2);
    p_p2p_cntx->my_p2p_data_sn++;
    // Length
    MEMCPY_REV(&p_data_cfm->com_hdr.grp_hdr.len, &len, BYTE_2);
    
    // CRC32
    if (P2P_GRP_HDR_GET_CRC(p2p_info))
    {
        util_cal_crc32((uint8_t *)p_data_cfm, buf_len);
        
        buf_len += UTIL_CRC_LEN;
    }
    
    ret = sock_send_data(sockfd, p_peer_sock_addr, (uint8_t *)p_data_cfm, buf_len);
    
    FREE_M(p_data_cfm);
    
    return (ret);
}

int32_t p2p_data_cfm_ind (int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr)
{
    P2P_DATA_CFM_IND_T *p_data_cfm_ind = (P2P_DATA_CFM_IND_T *)p_sub_hdr;
    uint32_t data_len;

    MEMCPY_REV2(&p_data_cfm_ind->sub.result, BYTE_4);

    data_len = (p_data_cfm_ind->tlv_hdr.tlv & P2P_TLV_HDR_LEN_MASK) >> P2P_TLV_HDR_LEN_BIT;

    DBG_PRINT(DBG_P2P, DBG_NONE, (void *)"Data Length = %d\n", data_len);
    DBG_PRINT(DBG_P2P, DBG_NONE, (void *)"Result = %d\n", p_data_cfm_ind->sub.result);

#if (P2P_TEST == ENABLED)
#if (P2P_TEST_PINGPONG == ENABLED)
    p2p_data_client_test();
#endif // P2P_TEST_PINGPONG
#endif // P2P_TEST
    
    return SUCCESS_;
}

