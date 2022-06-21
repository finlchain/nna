/**
    @file p2p.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

P2P_CNTX_T g_p2p_cntx;

static void p2p_rx_init(bool b_init)
{
    if (b_init)
    {
        RX_CBS_T rx_cbs;

        MEMSET_M(&rx_cbs, 0x00, sizeof(RX_CBS_T));

        rx_cbs.rx_evt_handle_cb = p2p_sock_event_handler;
        rx_cb_set(&rx_cbs);
    }
}

static void p2p_cntx_init(bool b_init)
{
    if (b_init)
    {
        MEMSET_M(&g_p2p_cntx, 0x00, sizeof(P2P_CNTX_T));
    }

    json_node_info_update();
    json_p2p_udpate(&g_p2p_cntx);
}

void p2p_init(bool b_init)
{
    p2p_cntx_init(b_init);

    p2p_sock_init(b_init);
    p2p_rx_init(b_init);
}

P2P_CNTX_T *p2p_get_cntx(void)
{
    return(&g_p2p_cntx);
}

#if (P2P_TEST == ENABLED)
void p2p_data_client_test(void)
{
    #define DATA_BUF_SIZE 800
    
    uint8_t data_buf[DATA_BUF_SIZE];
    //uint8_t char_data[] = "abcdefghijklmnopqrstuvwxyz";
    uint64_t dst_addr;
    int32_t cnt;
    SOCK_CNTX_T *p_sock_cntx = p2p_sock_cntx();
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();

    DBG_PRINT(DBG_CONS, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    for (cnt=0; cnt<DATA_BUF_SIZE; cnt++)
    {
        data_buf[cnt] = cnt;
    }

    dst_addr = p_p2p_cntx->my_p2p_addr.u64 + 1;

    //
#if 0//(UDP_CLI_CNNCT == ENABLED)
    p2p_data_req(p_sock_cntx->udp_cli_sock[UDP_CLI_1].sockfd, &p_sock_cntx->udp_cli_sock[UDP_CLI_1].peer.sock_addr, "key/mn/mn_pubkey.pem", data_buf, cnt, &dst_addr);
#endif // UDP_CLI_CNNCT
    
#if (TCP_CLI_CNNCT == ENABLED)
    DBG_PRINT(DBG_P2P, DBG_NONE, (void *)"sockfd = %d\n", p_sock_cntx->tcp_cli_sock[TCP_CLI_1].sockfd);
    if (p_sock_cntx->tcp_cli_sock[TCP_CLI_1].sockfd > 0)
    {
        p2p_data_req(p_sock_cntx->tcp_cli_sock[TCP_CLI_1].sockfd, NULL, "key/mn/mn_pubkey.pem", data_buf, cnt, &dst_addr);
    }
#endif // TCP_CLI_CNNCT
}
#endif // P2P_TEST

//
void p2p_send_join_req(int32_t sockfd)
{
    P2P_GRP_HDR_T grp_hdr;
    P2P_CNTX_T *p_p2p_cntx = p2p_get_cntx();
    //P2P_NODE_INFO_T node_info;

    if (p_p2p_cntx->my_node_info.node_rule & P2P_NODE_RULE_NN)
    {
        ASSERT_M(p_p2p_cntx->my_p2p_addr.u64 == p_p2p_cntx->my_cluster_root);
        
        grp_hdr.dst_addr = P2P_NULL_ADDR;
    }
    else
    {
        grp_hdr.dst_addr = p_p2p_cntx->my_cluster_root;
    }
    //grp_hdr.src_addr = p_p2p_cntx->my_p2p_addr.u64;
    
    p2p_cmd_join_req(sockfd, NULL, &grp_hdr, &p_p2p_cntx->my_node_info);
}

//
void p2p_tcp_client_join_proc(SOCK_CNTX_T *p_sock_cntx, uint32_t sock_idx)
{
#if (TCP_CLI_CNNCT == ENABLED)
    p2p_send_join_req(p_sock_cntx->tcp_cli_sock[sock_idx].sockfd);
#endif // TCP_CLI_CNNCT
}

void *t_p2p_main(void *p_data)
{
    pid_t pid; // process id
    
    char* thread_name = (char*)p_data;
    bool exe_thread = true;
    int task_ret = TASK_EXIT_NORMAL;

#if (defined (_WIN32) || defined (_WIN64))
    pthread_t tid; // thread id
    
    pid = GetCurrentProcessId();
    tid = pthread_self();
#else
    pid_t tid;

    pid = getpid();
    tid = syscall(SYS_gettid);

    setpriority(PRIO_PROCESS, tid, g_tid_nice[P2P_THREAD_IDX]);
#endif

    DBG_PRINT(DBG_CLI, DBG_TRACE, (void *)"%s\n", __FUNCTION__);
    DBG_PRINT(DBG_TX, DBG_INFO, (void *)"%s is started.! - pid(%d), tid(%d)\n", thread_name, pid, tid);

    p2p_timer_run();

    while (exe_thread)
    {
        p2p_task_msg_handler();

        usleep(10);
    }

    pthread_exit(&task_ret);
    
    return (void *)p_data;
}

void p2p_task_init(void)
{
    p2p_init(true);
    p2p_task_msg_init();
}

