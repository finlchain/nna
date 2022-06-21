/**
    @file p2p_task_msg.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

LIST_T p2p_task_list, p2p_task_pool;
TASK_MSG_ITEM_T p2p_task_items[P2P_TASK_MSG_POOL_SIZE];

void p2p_task_msg_init(void)
{
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    task_msg_init(&p2p_task_list, &p2p_task_pool,P2P_TASK_MSG_POOL_SIZE, p2p_task_items);
}

void p2p_task_msg_handler(void)
{
    TASK_MSG_ITEM_T *p_item;

    DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);

    // Get the item from LIST
    p_item = task_get_msg(&p2p_task_list);
    if (p_item)
    {
        // Process
        if (p_item->event == P2P_TASK_MSG_EVENT_01)
        {
            DBG_PRINT(DBG_P2P, DBG_NONE, (void *)"P2P_TASK_MSG_EVENT_01\n");
#if (P2P_TEST == ENABLED)
            p2p_data_client_test();
#endif // P2P_TEST
        }
        else if (p_item->event == P2P_TASK_MSG_EVENT_02)
        {
            DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"P2P_TASK_MSG_EVENT_02\n");

            sock_open_tcp_client_proc(p2p_sock_cntx());
        }
        else if (p_item->event == P2P_TASK_MSG_EVENT_03)
        {
            uint32_t sock_idx;

            DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"P2P_TASK_MSG_EVENT_03\n");

            MEMCPY_M(&sock_idx, p_item->buf, p_item->len);

            DBG_PRINT(DBG_CONS, DBG_INFO, (void *)"P2P_TASK_MSG_EVENT_03 sock_idx(%d)\n", sock_idx);
            
            sock_open_tcp_client_with_reopen(p2p_sock_cntx(), sock_idx);
        }
#if (P2P_PKT_IND_SEPARATED == ENABLED)
        else if (p_item->event == P2P_TASK_MSG_EVENT_04)
        {
            int32_t sockfd;
            struct sockaddr_in peer_sock_addr, *p_peer_sock_addr;
            P2P_SRVC_IND_T *p_p2p_prvc_ind;
            uint32_t pkt_len;

            DBG_PRINT(DBG_CONS, DBG_NONE, (void *)"P2P_TASK_MSG_EVENT_04\n");

            pkt_len = 0;
            MEMCPY_M(&sockfd, &p_item->buf[pkt_len], BYTE_4);
            pkt_len += BYTE_4;

            MEMCPY_M(&peer_sock_addr, &p_item->buf[pkt_len], sizeof(struct sockaddr_in));
            pkt_len += sizeof(struct sockaddr_in);

            if (peer_sock_addr.sin_addr.s_addr == 0x00000000)
            {
                p_peer_sock_addr = NULL;
            }
            else
            {
                p_peer_sock_addr = &peer_sock_addr;
            }

            p_p2p_prvc_ind = (P2P_SRVC_IND_T *)&p_item->buf[pkt_len];

            p2p_sock_pkt_ind(sockfd, p_peer_sock_addr, p_p2p_prvc_ind);
        }
#endif // P2P_PKT_IND_SEPARATED

        // Return the list into POOL
        task_clr_msg(&p2p_task_pool, &p2p_task_list, p_item);
    }
}

