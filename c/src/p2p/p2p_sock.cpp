/**
    @file p2p_sock.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

SOCK_CNTX_T g_p2p_sock_cntx;

// Local
static int32_t p2p_sock_pkt_cmd_grp_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr)
{
    int32_t ret = ERROR_;
    uint32_t type_cmd, len;

    type_cmd = P2P_TLV_HDR_GET_TYPE_CMD(p_sub_hdr->tlv_hdr.tlv);
    len = P2P_TLV_HDR_GET_LEN(p_sub_hdr->tlv_hdr.tlv);

    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"(%s) type_cmd [0x%04X] len(%d)\n", __FUNCTION__, type_cmd, len);

    switch (type_cmd)
    {
    case P2P_SRVC_CMD_JOIN_REQ:
        ret = p2p_cmd_join_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_sub_hdr);
        break;
    case P2P_SRVC_CMD_JOIN_RESP:
        ret = p2p_cmd_join_cfm(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_sub_hdr);
        break;
#if (P2P_PUBKEY_NOTI == ENABLED)
    case P2P_SRVC_CMD_PUBKEY_NOTI:
        ret = p2p_cmd_pubkey_noti_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_sub_hdr);
        break;
#endif // P2P_PUBKEY_NOTI
    default:
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"(%s) unknown service type error - type_cmd [0x%04X]\n", __FUNCTION__, type_cmd);
        break;
    }

    return (ret);
}

static int32_t p2p_sock_pkt_mgmt_grp_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr)
{
    int32_t ret = ERROR_;
    uint32_t type_cmd, len;

    type_cmd = P2P_TLV_HDR_GET_TYPE_CMD(p_sub_hdr->tlv_hdr.tlv);
    len = P2P_TLV_HDR_GET_LEN(p_sub_hdr->tlv_hdr.tlv);

    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s) type_cmd [0x%04X] len(%d)\n", __FUNCTION__, type_cmd, len);

    switch (type_cmd)
    {
        default:
            DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"(%s) unknown service type error\n", __FUNCTION__);
            break;
    }

    return (ret);
}

static int32_t p2p_sock_pkt_data_grp_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_GRP_HDR_T *p_grp_hdr, P2P_SUB_HDR_T *p_sub_hdr)
{
    int32_t ret = ERROR_;
    uint32_t type_cmd, len;

    type_cmd = P2P_TLV_HDR_GET_TYPE_CMD(p_sub_hdr->tlv_hdr.tlv);
    len = P2P_TLV_HDR_GET_LEN(p_sub_hdr->tlv_hdr.tlv);

    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"(%s) type_cmd(0x%04X) len(%d)\n", __FUNCTION__, type_cmd, len);

    switch (type_cmd)
    {
    case P2P_SRVC_DATA_REQ:
        ret = p2p_data_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_sub_hdr);
        break;

    case P2P_SRVC_DATA_CFM:
        ret = p2p_data_cfm_ind(rx_sockfd, p_peer_sock_addr, p_grp_hdr, p_sub_hdr);
        break;
    
    default:
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"(%s) unknown cmd error\n", __FUNCTION__);
        break;
    }

    return (ret);
}

int32_t p2p_sock_pkt_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_SRVC_IND_T *p_msg)
{
    int32_t ret = ERROR_;
    
    uint32_t tlv_idx = 0;
    uint32_t next = 0;

    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"**************************************************\n");
    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"[Received message] - rx_sockfd(%d)\n", rx_sockfd);

    do
    {
        P2P_SUB_HDR_T *p_sub_hdr;
        uint32_t type_cmd, len;

        p_sub_hdr = (P2P_SUB_HDR_T *)&p_msg->buf[tlv_idx];
        MEMCPY_REV2(&p_sub_hdr->tlv_hdr.tlv, BYTE_4);

        next = P2P_TLV_HDR_GET_NEXT(p_sub_hdr->tlv_hdr.tlv);
        type_cmd = P2P_TLV_HDR_GET_TYPE_CMD(p_sub_hdr->tlv_hdr.tlv);
        len = P2P_TLV_HDR_GET_LEN(p_sub_hdr->tlv_hdr.tlv);

        DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"tlv_idx(%d) : type_cmd(0x%04X), LEN(%d)\n", tlv_idx, type_cmd, len);
        
        switch (type_cmd & P2P_SRVC_TYPE_GRP_MASK)
        {
        case P2P_SRVC_CMD_GROUP:
            ret = p2p_sock_pkt_cmd_grp_ind(rx_sockfd, p_peer_sock_addr, &p_msg->grp_hdr, p_sub_hdr);
            break;

        case P2P_SRVC_MGMT_GROUP:
            ret = p2p_sock_pkt_mgmt_grp_ind(rx_sockfd, p_peer_sock_addr, &p_msg->grp_hdr, p_sub_hdr);
            break;

        case P2P_SRVC_DATA_GROUP:
            ret = p2p_sock_pkt_data_grp_ind(rx_sockfd, p_peer_sock_addr, &p_msg->grp_hdr, p_sub_hdr);
            break;
            
        default:
            DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"(%s) unknown type error\n", __FUNCTION__);
            break;
        }

        tlv_idx += len;
    } while (next);
    
    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"**************************************************\n");

    return (ret);
}

static void p2p_sock_pkt_handler(int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, SOCK_CNTX_T *p_sock_cntx, int32_t buf_len, SOCK_RCV_BUF_T *p_rbuf)
{
    P2P_SRVC_IND_T *p_p2p_prvc_ind;
    uint32_t idx = 0;
    int32_t crc_chk, dec_chk;
    
    uint32_t p2p_info;
    uint16_t p2p_seq_num;
    uint16_t p2p_len;
    
    uint8_t rcv_pkt_sec_buf[SOCK_CFM_PKT_LEN];

    int32_t tot_buf_len = buf_len; // for debugging
    
    do
    {
        //ASSERT_M(buf_len >= P2P_GRP_HDR_LEN);
        if (buf_len < (int32_t)P2P_GRP_HDR_LEN)
        {
            DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"Packet Incompleted 1 - idx(%d) buf_len(%d) tot_buf_len(%d)\n", idx, buf_len, tot_buf_len);
            
            p_rbuf->buf = (uint8_t *)MALLOC_M(buf_len);
            if (p_rbuf->buf)
            {
                MEMCPY_M(p_rbuf->buf, &p_sock_cntx->rcv_buf[idx], buf_len);
                p_rbuf->buf_len = buf_len;

                DBG_DUMP(DBG_SOCKET, DBG_NONE, (void *) "rcv_tmp_buf", p_rbuf->buf, p_rbuf->buf_len);
            }
            else
            {
                DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"rcv_tmp_buf Alloc Error 1\n");
            }
            
            return;
        }
        
        p_p2p_prvc_ind = (P2P_SRVC_IND_T *)&p_sock_cntx->rcv_buf[idx];

        MEMCPY_REV(&p2p_info, &p_p2p_prvc_ind->grp_hdr.info, BYTE_4);
        MEMCPY_REV(&p2p_seq_num, &p_p2p_prvc_ind->grp_hdr.seq_num, BYTE_2);
        MEMCPY_REV(&p2p_len, &p_p2p_prvc_ind->grp_hdr.len, BYTE_2);

        p2p_len += P2P_GRP_HDR_LEN;
        
        // CRC32
        if (P2P_GRP_HDR_GET_CRC(p2p_info))
        {
            //ASSERT_M(p_p2p_prvc_ind->grp_hdr.len >= UTIL_CRC_LEN);
            
            // Check CRC32
            crc_chk = util_chk_crc32((uint8_t *)p_p2p_prvc_ind, p2p_len);
            
            p2p_len += UTIL_CRC_LEN;
        }
        else
        {
            crc_chk = SUCCESS_;
        }

        // Error - Packet Length
        if (p2p_len > P2P_LEN_MAX)
        {
            DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"Packet Length Error - p2p_len(%d)\n", p2p_len);
            return;
        }

        DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"buf_len = %d, p2p_len = %d\n", buf_len, p2p_len);
        //ASSERT_M(buf_len >= (p2p_len));
        if (buf_len < (p2p_len))
        {
            DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"Packet Incompleted 2 - idx(%d) buf_len(%d) tot_buf_len(%d)\n", idx, buf_len, tot_buf_len);

            p_rbuf->buf = (uint8_t *)MALLOC_M(buf_len);
            if (p_rbuf->buf)
            {
                MEMCPY_M(p_rbuf->buf, &p_sock_cntx->rcv_buf[idx], buf_len);
                p_rbuf->buf_len = buf_len;

                DBG_DUMP(DBG_SOCKET, DBG_NONE, (void *) "rcv_tmp_buf", p_rbuf->buf, p_rbuf->buf_len);
            }
            else
            {
                DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"rcv_tmp_buf Alloc Error 2\n");
            }
            
            return;
        }
#if 0 // Not yet opened
        // Error - Packet Sequence Number
        if ((p2p_seq_num - p_rbuf->priv_seq_num) > P2P_SEQ_NUM_OVERFLOW)
        {
            DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"Packet Sequence Number Error - p2p_len(%d)\n", p2p_len);
            return;
        }
#endif
        p_rbuf->priv_seq_num = p2p_seq_num;

        // 
        MEMCPY_REV2(&p_p2p_prvc_ind->grp_hdr.dst_addr, P2P_ADDR_LEN);
        MEMCPY_REV2(&p_p2p_prvc_ind->grp_hdr.src_addr, P2P_ADDR_LEN);
        MEMCPY_REV2(&p_p2p_prvc_ind->grp_hdr.timestamp, P2P_TIMESTAMP_LEN);
        MEMCPY_REV2(&p_p2p_prvc_ind->grp_hdr.info, BYTE_4);
        MEMCPY_REV2(&p_p2p_prvc_ind->grp_hdr.seq_num, BYTE_2);
        MEMCPY_REV2(&p_p2p_prvc_ind->grp_hdr.len, BYTE_2);
        
        DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"ENC = %d\n", P2P_GRP_HDR_GET_ENC(p2p_info));
        
        // Decryption
        switch (P2P_GRP_HDR_GET_ENC(p2p_info))
        {
        case P2P_GRP_HDR_ENC_ECIES:
        {
            CONS_CNTX_T *p_cons_cntx = cons_get_cntx();
            
            uint8_t *p_msg, *p_dec_msg;
            uint32_t dec_msg_len;
    
            ASSERT_M (p_p2p_prvc_ind->grp_hdr.len > (OPENSSL_ECIES_R_LEN + OPENSSL_ECIES_MAC_LEN));

            p_msg = rcv_pkt_sec_buf;
            p_dec_msg = &p_msg[P2P_GRP_HDR_LEN];
    
            DBG_DUMP(DBG_SOCKET, DBG_NONE, (void *)"p_rcv_enc_msg", (uint8_t *)p_p2p_prvc_ind->buf, p_p2p_prvc_ind->grp_hdr.len);
            DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"my_prikey_path (%s)\n", p_cons_cntx->my_prikey_path);
            
            dec_chk = p2p_ecies_decrypt(p_cons_cntx->my_prikey_path, NULL, 0, NULL, 0, 
                            (uint8_t *)p_p2p_prvc_ind->buf, p_p2p_prvc_ind->grp_hdr.len, 
                            (uint8_t **) &p_dec_msg, &dec_msg_len);
            
            if (dec_chk == SUCCESS_)
            {
                DBG_DUMP(DBG_SOCKET, DBG_NONE, (void *)"p_dec_msg", (uint8_t *)p_dec_msg, dec_msg_len);
                
                MEMCPY_M(p_msg, &p_p2p_prvc_ind->grp_hdr, P2P_GRP_HDR_LEN);
    
                p_p2p_prvc_ind = (P2P_SRVC_IND_T *)p_msg;
    
                p_p2p_prvc_ind->grp_hdr.len = dec_msg_len;
                MEMCPY_M(p_p2p_prvc_ind->buf, p_dec_msg, dec_msg_len);
    
                DBG_DUMP(DBG_SOCKET, DBG_NONE, (void *)"p_msg", (uint8_t *)p_msg, P2P_GRP_HDR_LEN+dec_msg_len);
            }
            else
            {
                //ASSERT_M(0);
            }
            break;
        }
        default :
            dec_chk = SUCCESS_;
            break;
        }
        
        if ((crc_chk == SUCCESS_) && (dec_chk == SUCCESS_))
        {
#if (P2P_PKT_IND_SEPARATED == ENABLED)
            uint8_t pkt_buf[SOCK_CFM_PKT_LEN];
            uint8_t *pkt_buf;
            uint32_t pkt_len;
            int32_t ret;

            //pkt_buf = (uint8_t *)MALLOC_M(SOCK_CFM_PKT_LEN);

            //pkt_len = BYTE_4 + sizeof(struct sockaddr_in) + (sizeof(P2P_GRP_HDR_T) + p_p2p_prvc_ind->grp_hdr.len);
            
            pkt_len = 0;
            
            MEMCPY_M(&pkt_buf[pkt_len], &sockfd, BYTE_4);
            pkt_len += BYTE_4;

            if (p_peer_sock_addr)
            {
                MEMCPY_M(&pkt_buf[pkt_len], p_peer_sock_addr, sizeof(struct sockaddr_in));
            }
            else
            {
                MEMSET_M(&pkt_buf[pkt_len], 0x00, sizeof(struct sockaddr_in));
            }
            pkt_len += sizeof(struct sockaddr_in);

            MEMCPY_M(&pkt_buf[pkt_len], p_p2p_prvc_ind, sizeof(P2P_GRP_HDR_T)+p_p2p_prvc_ind->grp_hdr.len);
            pkt_len += (sizeof(P2P_GRP_HDR_T)+p_p2p_prvc_ind->grp_hdr.len);

            ret = task_send_msg(&p2p_task_pool, &p2p_task_list, (uint8_t *)pkt_buf, pkt_len, false, P2P_TASK_MSG_EVENT_04);
            if (ret == ERROR_)
            {
                ASSERT_M(0);
            }

            //FREE_M(pkt_buf);
#else
            p2p_sock_pkt_ind(sockfd, p_peer_sock_addr, p_p2p_prvc_ind);
#endif // P2P_PKT_IND_SEPARATED
        }
        else
        {
            DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"(%s) Error CRC = %d, DEC = %d \n", __FUNCTION__, crc_chk, dec_chk);
            //ASSERT_M(0);
        }
        
        idx += p2p_len;
        buf_len -= p2p_len;
    } while (buf_len);
}

#if ((UDP_CLI_CNNCT == ENABLED) || (UDP_SVR_CNNCT == ENABLED))
static void p2p_sock_udp_mod_ind(SOCK_CNTX_T *p_sock_cntx, bool server, uint32_t sock_idx)
{
    //P2P_GRP_HDR_T *p_grp_hdr;
    int32_t ret;

    int32_t sockfd;
    struct sockaddr_in peer_sock_addr;
    int32_t peer_addr_size = sizeof(struct sockaddr_in);

    SOCK_RCV_BUF_T *p_rbuf;
    
    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s) - start\n", __FUNCTION__);
    DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"server(%d) sock_idx(%d)\n", server, sock_idx);

    if (server)
    {
#if (UDP_SVR_CNNCT == ENABLED)
        sockfd = p_sock_cntx->udp_svr_sock[sock_idx].sockfd;
        p_rbuf = &p_sock_cntx->udp_svr_sock[sock_idx].rbuf;
#else
        ASSERT_M(0);
#endif // UDP_SVR_CNNCT
    }
    else
    {
#if (UDP_CLI_CNNCT == ENABLED)
        sockfd = p_sock_cntx->udp_cli_sock[sock_idx].sockfd;
        p_rbuf = &p_sock_cntx->udp_cli_sock[sock_idx].rbuf;
#else
        ASSERT_M(0);
#endif // UDP_CLI_CNNCT
    }

    //p_grp_hdr = (P2P_GRP_HDR_T *)p_sock_cntx->rcv_buf;

    ASSERT_M(SOCK_CFM_BUF_LEN >= p_rbuf->buf_len);
    MEMCPY_M(p_sock_cntx->rcv_buf, p_rbuf->buf, p_rbuf->buf_len);
    
    ret = recvfrom(sockfd, &p_sock_cntx->rcv_buf[p_rbuf->buf_len], SOCK_CFM_BUF_LEN-p_rbuf->buf_len, 0, (struct sockaddr*)&peer_sock_addr, (socklen_t *)&peer_addr_size);
    if (ret < 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"error 1\n");
        return;
    }
    else if (ret == 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"error 2\n");
        return;
    }

    ret += p_rbuf->buf_len;
    //ASSERT_M(p_rbuf->buf_len == 0);
    FREE_M(p_rbuf->buf);
    p_rbuf->buf_len = 0;

    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"peer size(%d) addr(0x%08X) port(0x%04X)\n", peer_addr_size, peer_sock_addr.sin_addr.s_addr, ntohs(peer_sock_addr.sin_port));
    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"buf : %d\n", ret);
    DBG_DUMP(DBG_SOCKET, DBG_NONE, (void *) "rcv_buf", p_sock_cntx->rcv_buf, ret);
    
    if (util_is_my_ip_addr(peer_sock_addr.sin_addr.s_addr) == ERROR_)
    {
        p2p_sock_pkt_handler(sockfd, &peer_sock_addr, p_sock_cntx, ret, p_rbuf);
    }

    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s) - end\n", __FUNCTION__);
}

#endif // UDP_CLI_CNNCT || UDP_SVR_CNNCT

#if ((TCP_CLI_CNNCT == ENABLED) || (TCP_SVR_CNNCT == ENABLED))
void p2p_sock_err_handle(SOCK_CNTX_T *p_sock_cntx, bool server, uint32_t sock_idx, int32_t sockfd)
{
    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"server(%d) sock_idx(%d) sockfd(%d)\n", server, sock_idx, sockfd);

    cons_peer_del_ind(sockfd);
    
    if (server)
    {
#if (TCP_SVR_CNNCT == ENABLED)
        sock_tcp_usr_close(p_sock_cntx, sockfd, sock_idx);
#endif // TCP_SVR_CNNCT
    }
    else
    {
        P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
        
#if (TCP_CLI_CNNCT == ENABLED)
        sock_close_tcp_client(p_sock_cntx, sock_idx);

        if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
        {
            //timer_sw_reg((uint8_t *)"p2p_sc4", true, 1000000, 0, p2p_timer_sock_conn_with_idx, sock_idx);
        }
#endif // TCP_CLI_CNNCT
    }
}

#if (USE_SOCK_SELECT == ENABLED)
static void p2p_sock_tcp_mod_ind_select(SOCK_CNTX_T *p_sock_cntx, bool server, uint32_t sock_idx)
{
    int32_t ret;
    
    int32_t sockfd;
//    struct sockaddr_in sock_addr;
//    int32_t sock_addr_size;
    
    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s) server(%d) sock_idx(%d) - start\n", __FUNCTION__, server, sock_idx);

#if (TCP_SVR_CNNCT == ENABLED)

#endif // TCP_SVR_CNNCT

    if (server)
    {
#if (TCP_SVR_CNNCT == ENABLED)
        //
#endif // TCP_SVR_CNNCT
    }
    else
    {
#if (TCP_CLI_CNNCT == ENABLED)
        sockfd = p_sock_cntx->tcp_cli_sock[sock_idx].sockfd;
#endif // TCP_CLI_CNNCT
    }

    ret = recv(sockfd, p_sock_cntx->rcv_buf, P2P_GRP_HDR_LEN, 0);
    if (ret <= 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"%s : recv error - server(%d), sock_idx(%d), sockfd(%d)\n", __FUNCTION__, server, sock_idx, sockfd);
        p2p_sock_err_handle(p_sock_cntx, server, sock_idx, sockfd);
        
        return;
    }

    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"1st ret=%d\n", ret);

    if (ret == P2P_GRP_HDR_LEN)
    {
        P2P_GRP_HDR_T *p_grp_hdr;

        p_grp_hdr = (P2P_GRP_HDR_T *)p_sock_cntx->rcv_buf;
        
        if (p_grp_hdr->len)
        {
            ret = recv(sockfd, &p_sock_cntx->rcv_buf[P2P_GRP_HDR_LEN], p_grp_hdr->len, 0);
            
            if (ret < 0)
            {
                ASSERT_M(0);
            }

            DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"2nd ret=%d p_grp_hdr->len=%d\n", ret, p_grp_hdr->len);
            DBG_DUMP(DBG_SOCKET, DBG_NONE, (void *)"p_sdp_req->data", &p_sock_cntx->rcv_buf[P2P_GRP_HDR_LEN], p_grp_hdr->len);

            if (ret != p_grp_hdr->len)
            {
                DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"2nd ret=%d\n", ret);
                ASSERT_M (0);
            }
        }
        
#if (P2P_PKT_IND_SEPARATED == ENABLED)
        uint8_t pkt_buf[SOCK_CFM_PKT_LEN];
        uint32_t pkt_len;
        P2P_SRVC_IND_T *p_p2p_prvc_ind = (P2P_SRVC_IND_T *)p_sock_cntx->rcv_buf;

        pkt_len = 0;
        
        MEMCPY_M(&pkt_buf[pkt_len], &sockfd, BYTE_4);
        pkt_len += BYTE_4;
        
        MEMSET_M(&pkt_buf[pkt_len], 0x00, sizeof(struct sockaddr_in));
        pkt_len += sizeof(struct sockaddr_in);

        MEMCPY_M(&pkt_buf[pkt_len], p_p2p_prvc_ind, sizeof(P2P_GRP_HDR_T)+p_p2p_prvc_ind->grp_hdr.len);
        pkt_len += (sizeof(P2P_GRP_HDR_T)+p_p2p_prvc_ind->grp_hdr.len);

        ret = task_send_msg(&p2p_task_pool, &p2p_task_list, (uint8_t *)pkt_buf, pkt_len, false, P2P_TASK_MSG_EVENT_04);
        if (ret == ERROR_)
        {
            ASSERT_M(0);
        }
#else
        p2p_sock_pkt_ind(sockfd, NULL, (P2P_SRVC_IND_T *)p_sock_cntx->rcv_buf);
#endif // P2P_PKT_IND_SEPARATED
    }
    else
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"1st ret=%d\n", ret);
        //ASSERT_M (0);
    }

    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s) - end\n", __FUNCTION__);
}
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
static void p2p_sock_tcp_mod_ind_epoll(SOCK_CNTX_T *p_sock_cntx, bool server, uint32_t sock_idx)
{
    int32_t ret;
    
    int32_t sockfd;
    //struct sockaddr_in sock_addr;
    //int32_t sock_addr_size;
    SOCK_RCV_BUF_T *p_rbuf;
    
    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"(%s) server(%d) sock_idx(%d) - start\n", __FUNCTION__, server, sock_idx);
    get_current_rss_monitor(DBG_NONE, (char *)"1");

    if (server)
    {
#if (TCP_SVR_CNNCT == ENABLED)
        sockfd = p_sock_cntx->tcp_curr_sock_fd;
        p_rbuf = p_sock_cntx->tcp_curr_rbuf;
#else
        ASSERT_M(0);
#endif // TCP_SVR_CNNCT
    }
    else
    {
#if (TCP_CLI_CNNCT == ENABLED)
        sockfd = p_sock_cntx->tcp_cli_sock[sock_idx].sockfd;
        p_rbuf = &p_sock_cntx->tcp_cli_sock[sock_idx].rbuf;
#else
        ASSERT_M(0);
#endif // TCP_CLI_CNNCT
    }

    ASSERT_M(SOCK_CFM_BUF_LEN >= p_rbuf->buf_len);
    if (p_rbuf->buf)
    {
        ASSERT_M(p_rbuf->buf_len);
        MEMCPY_M(p_sock_cntx->rcv_buf, p_rbuf->buf, p_rbuf->buf_len);
    }
    
    ret = recv(sockfd, &p_sock_cntx->rcv_buf[p_rbuf->buf_len], SOCK_CFM_BUF_LEN-p_rbuf->buf_len, 0);
    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"buf : %d\n", ret);
    DBG_DUMP(DBG_SOCKET, DBG_NONE, (void *) "rcv_buf", p_sock_cntx->rcv_buf, ret);

    ret += p_rbuf->buf_len;
    //ASSERT_M(p_rbuf->buf_len == 0);
    
    FREE_M(p_rbuf->buf);
    p_rbuf->buf_len = 0;
                    
    if (ret <= 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"%s : recv error - server(%d), sock_idx(%d), sockfd(%d)\n", __FUNCTION__, server, sock_idx, sockfd);
        p2p_sock_err_handle(p_sock_cntx, server, sock_idx, sockfd);
        
        return;
    }
    else
    {
        do
        {
            P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

            if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
            {
                if (server)
                {
                    //
                }
                else
                {
                    //
                }
            }

            p2p_sock_pkt_handler(sockfd, NULL, p_sock_cntx, ret, p_rbuf);

        } while (0);
    }

    get_current_rss_monitor(DBG_NONE, (char *)"2");
    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"(%s) - end\n", __FUNCTION__);
}

#endif // USE_SOCK_EPOLL

#endif // TCP_CLI_CNNCT || TCP_SVR_CNNCT

#if (USE_SOCK_SELECT == ENABLED)
static int32_t p2p_sock_tcp_svr_usr_search_select(SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx, LIST_T *p_list, fd_set *p_event_fd)
{
    LIST_ITEM_T *p_item;
    SOCK_TCP_USR_ITEM_T *p_tcp_usr_item;

    if( p_list->num_items == 0 )
    {
        return;
    }

    p_item = p_list->head;

    while (!p_item)
    {
        p_tcp_usr_item = (SOCK_TCP_USR_ITEM_T *)p_item;
        if (FD_ISSET(p_tcp_usr_item->sockfd, p_event_fd) != 0)
        {
            p_sock_cntx->tcp_curr_sock_fd = p_tcp_usr_item->sockfd;
            p2p_sock_tcp_mod_ind_select(p_sock_cntx, true, svr_idx);
            return (SUCCESS_);
        }

        
        p_item = p_item->next;
    }

    return (ERROR_);
}

static P2P_SOCK_EVT_E p2p_sock_action_select(SOCK_CNTX_T *p_sock_cntx)
{
    uint32_t sock_idx;
    
#if (UDP_CLI_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->udp_cli_num; sock_idx++)
    {
        if (FD_ISSET(p_sock_cntx->udp_cli_sock[sock_idx].sockfd, &p_sock_cntx->event_fd) != 0) 
        {
            p2p_sock_udp_mod_ind(p_sock_cntx, false);
            return P2P_SOCK_EVT_UDP_CLI_IND;
        }
    }
#endif // UDP_CLI_CNNCT

#if (UDP_SVR_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->udp_svr_num; sock_idx++)
    {
        if (FD_ISSET(p_sock_cntx->udp_svr_sock[sock_idx].sockfd, &p_sock_cntx->event_fd) != 0) 
        {
            p2p_sock_udp_mod_ind(p_sock_cntx, true, sock_idx);
            return P2P_SOCK_EVT_UDP_SVR_USER_IND;
        }
    }
#endif // UDP_SVR_CNNCT

#if (TCP_CLI_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->tcp_cli_num; sock_idx++)
    {
        if (FD_ISSET(p_sock_cntx->tcp_cli_sock[sock_idx].sockfd, &p_sock_cntx->event_fd) != 0) 
        {
            p2p_sock_tcp_mod_ind_select(p_sock_cntx, false, sock_idx);
            return P2P_SOCK_EVT_TCP_CLI_IND;
        }
    }
#endif // TCP_CLI_CNNCT

#if (TCP_SVR_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->tcp_svr_num; sock_idx++)
    {
        if (FD_ISSET(p_sock_cntx->tcp_svr_sock[sock_idx].sockfd, &p_sock_cntx->event_fd) != 0)
        {
            sock_process_usr_accept (p_sock_cntx, sock_idx);
            return P2P_SOCK_EVT_TCP_SVR_USER_ACCEPT;
        }

        if (p2p_sock_tcp_svr_usr_search_select(p_sock_cntx, sock_idx, p_sock_cntx->tcp_usrs[sock_idx].tcp_usr_list, &p_sock_cntx->event_fd) == SUCCESS_)
        {
            return P2P_SOCK_EVT_TCP_SVR_USER_IND;
        }
    }
#endif // TCP_SVR_CNNCT

    return P2P_SOCK_EVT_ERROR;
}
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
static P2P_SOCK_EVT_E p2p_sock_action_epoll(SOCK_CNTX_T *p_sock_cntx, int32_t nfds)
{
    int32_t cnt;
    uint32_t sock_idx, searched;

    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);
    
    searched = false;

    for (cnt=0; cnt<nfds; cnt++)
    {
#if (UDP_CLI_CNNCT == ENABLED)
        for (sock_idx = 0; sock_idx < p_sock_cntx->udp_cli_num; sock_idx++)
        {
            if (p_sock_cntx->udp_cli_sock[sock_idx].sockfd == p_sock_cntx->events[cnt].data.fd) 
            {
                p2p_sock_udp_mod_ind(p_sock_cntx, false, sock_idx);
                //return P2P_SOCK_EVT_UDP_CLI_IND;
            	continue;
            }
        }
#endif // UDP_CLI_CNNCT
    
#if (UDP_SVR_CNNCT == ENABLED)
        searched = false;

        for (sock_idx = 0; sock_idx < p_sock_cntx->udp_svr_num; sock_idx++)
        {
            if (p_sock_cntx->udp_svr_sock[sock_idx].sockfd == p_sock_cntx->events[cnt].data.fd) 
            {
                p2p_sock_udp_mod_ind(p_sock_cntx, true, sock_idx);
                //return P2P_SOCK_EVT_UDP_SVR_USER_IND;
                searched = true;
                break;
            }
        }

        if (searched)
        {
            continue;
        }
#endif // UDP_SVR_CNNCT
    
#if (TCP_CLI_CNNCT == ENABLED)
        for (sock_idx = 0; sock_idx < p_sock_cntx->tcp_cli_num; sock_idx++)
        {
            if (p_sock_cntx->tcp_cli_sock[sock_idx].sockfd == p_sock_cntx->events[cnt].data.fd) 
            {
                p2p_sock_tcp_mod_ind_epoll(p_sock_cntx, false, sock_idx);
                //return P2P_SOCK_EVT_TCP_CLI_IND;
                continue;
            }
        }
#endif // TCP_CLI_CNNCT

#if (TCP_SVR_CNNCT == ENABLED)
        searched = false;
        for (sock_idx = 0; sock_idx < p_sock_cntx->tcp_svr_num; sock_idx++)
        {
            if (p_sock_cntx->tcp_svr_sock[sock_idx].sockfd == p_sock_cntx->events[cnt].data.fd)
            {
                int32_t sock_ret;
                sock_ret = sock_process_usr_accept(p_sock_cntx, sock_idx);
                if (sock_ret == SUCCESS_)
                {
                    //return P2P_SOCK_EVT_TCP_SVR_USER_ACCEPT;
                    searched = true;
                }

                break;
            }
        }

        if (searched)
        {
            continue;
        }

        SOCK_TCP_USR_ITEM_T *p_item;

        searched = false;
        for (sock_idx = 0; sock_idx < p_sock_cntx->tcp_svr_num; sock_idx++)
        {
            //sock_tcp_svr_usr_debug(&p_sock_cntx->tcp_usrs[sock_idx].tcp_usr_list);
            p_item = sock_tcp_svr_usr_search(&p_sock_cntx->tcp_usrs[sock_idx].tcp_usr_list, p_sock_cntx->events[cnt].data.fd);
            if (p_item)
            {
                p_sock_cntx->tcp_curr_sock_fd = p_item->sockfd;
                p_sock_cntx->tcp_curr_rbuf = &p_item->rbuf;
                p2p_sock_tcp_mod_ind_epoll(p_sock_cntx, true, sock_idx);
                //return P2P_SOCK_EVT_TCP_SVR_USER_IND;
                searched = true;
                break;
            }
        }

        if (searched)
        {
            continue;
        }
#endif // TCP_SVR_CNNCT
    }

    return (P2P_SOCK_EVT_SUCCESS);
}
#endif // USE_SOCK_EPOLL


// Global
SOCK_CNTX_T *p2p_sock_cntx(void)
{
    return (&g_p2p_sock_cntx);
}

void p2p_sock_init(bool b_init)
{
    sock_init(&g_p2p_sock_cntx, b_init);

    // Socket Open
    sock_open_server_proc(&g_p2p_sock_cntx);
    sock_open_udp_client_proc(&g_p2p_sock_cntx);
    sock_open_tcp_client_proc(&g_p2p_sock_cntx);
}

int32_t p2p_sock_event_handler(void)
{
    //P2P_SOCK_EVT_E evt_type;
    SOCK_CNTX_T *p_sock_cntx = &g_p2p_sock_cntx;

    int32_t ret;

    ret = sock_fd_wait(p_sock_cntx);

    if (ret < 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"ERROR\n");
        return P2P_SOCK_EVT_ERROR;
    }
    else if (ret == 0)
    {
        //DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"No Action\n");
        return P2P_SOCK_EVT_NONE;
    }

#if (USE_SOCK_SELECT == ENABLED)
    p2p_sock_action_select(p_sock_cntx);
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
    p2p_sock_action_epoll(p_sock_cntx, ret);
#endif // USE_SOCK_EPOLL
    
    return (SUCCESS_);
}

