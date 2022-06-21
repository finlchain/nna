/**
    @file socket.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

// Local
#if (USE_SOCK_EPOLL == ENABLED)
static int32_t sock_create_epoll(SOCK_CNTX_T *p_sock_cntx)
{
    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_sock_cntx->epoll_fd = epoll_create(MAX_EVENTS);
    if(p_sock_cntx->epoll_fd < 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"epoll create Fails.\n");
        ASSERT_M(0);
        return (ERROR_);
    }
    
    DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"epoll creation success\n");

    return (SUCCESS_);
}

static int32_t sock_epoll_non_blocking(int32_t sockfd)
{
    int32_t flags;

    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"fcntl\n");
        return -1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(sockfd, F_SETFL, flags) == -1)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"fcntl\n");
        return -1;
    }
    return 0;
}

static int32_t sock_epoll_fd_add(SOCK_CNTX_T *p_sock_cntx, int sockfd)
{
    struct epoll_event events;

    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    if (sock_epoll_non_blocking(sockfd) < 0)
    {
        ASSERT_M(0);
        return (ERROR_);
    }

    MEMSET_M(&events, 0x00, sizeof(struct epoll_event));
    
    /* event control set for read event */
    events.events = EPOLLIN;// | EPOLLET;
    events.data.fd = sockfd;

    if( epoll_ctl(p_sock_cntx->epoll_fd, EPOLL_CTL_ADD, sockfd, &events) < 0 )
    {
        DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"Failed epoll_cli_add\n");
        ASSERT_M(0);
        return (ERROR_);
    }

    return (SUCCESS_);
}

static int32_t sock_epoll_fd_del(SOCK_CNTX_T *p_sock_cntx, int sockfd)
{
    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    if( epoll_ctl(p_sock_cntx->epoll_fd, EPOLL_CTL_DEL, sockfd, NULL) < 0 )
    {
        DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"Failed epoll_cli_del\n");
        ASSERT_M(0);
        return (ERROR_);
    }

    return (SUCCESS_);
}
#endif // USE_SOCK_EPOLL

#if (UDP_SVR_CNNCT == ENABLED)
static void sock_init_udp_server (SOCK_INFO_T *p_svr_sock) 
{
    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    MEMSET_M(&p_svr_sock->local.sock_addr, 0x00, sizeof(struct sockaddr_in));
    
    p_svr_sock->local.sock_addr.sin_family=AF_INET;
    p_svr_sock->local.sock_addr.sin_addr.s_addr = p_svr_sock->local.ip_addr;
    p_svr_sock->local.sock_addr.sin_port = htons(p_svr_sock->local.port);

    p_svr_sock->local.mreq.imr_multiaddr.s_addr = p_svr_sock->local.mreq_ip_addr;
    p_svr_sock->local.mreq.imr_interface.s_addr = htonl(p_svr_sock->local.ip_addr);
}
#endif // UDP_SVR_CNNCT

#if (UDP_CLI_CNNCT == ENABLED)
static void sock_init_udp_client (SOCK_INFO_T *p_cli_sock)  
{
    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    MEMSET_M(&p_cli_sock->peer_svr.sock_addr, 0x00, sizeof(struct sockaddr_in));
    
    p_cli_sock->peer_svr.sock_addr.sin_family=AF_INET;
    p_cli_sock->peer_svr.sock_addr.sin_addr.s_addr = p_cli_sock->peer_svr.ip_addr;
    p_cli_sock->peer_svr.sock_addr.sin_port = htons(p_cli_sock->peer_svr.port);

    p_cli_sock->local.sock_addr.sin_family=AF_INET;
    p_cli_sock->local.sock_addr.sin_addr.s_addr = p_cli_sock->local.ip_addr;
    p_cli_sock->local.sock_addr.sin_port = htons(p_cli_sock->local.port);   
}
#endif // UDP_CLI_CNNCT

#if (TCP_SVR_CNNCT == ENABLED)
static void sock_init_tcp_server (SOCK_INFO_T *p_svr_sock)   
{
    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_svr_sock->local.sock_addr.sin_family=AF_INET;
    p_svr_sock->local.sock_addr.sin_addr.s_addr = p_svr_sock->local.ip_addr;
    p_svr_sock->local.sock_addr.sin_port = htons(p_svr_sock->local.port);
}
#endif // TCP_SVR_CNNCT

#if (TCP_CLI_CNNCT == ENABLED)
void sock_init_tcp_client (SOCK_INFO_T *p_cli_sock)  
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    if (p_cli_sock->auto_join)
    {
        p_cli_sock->peer_svr.sock_addr.sin_family=AF_INET;
        p_cli_sock->peer_svr.sock_addr.sin_addr.s_addr = p_cli_sock->peer_svr.ip_addr;
        p_cli_sock->peer_svr.sock_addr.sin_port = htons(p_cli_sock->peer_svr.port);
    }

    p_cli_sock->local.sock_addr.sin_family=AF_INET;
    p_cli_sock->local.sock_addr.sin_addr.s_addr = p_cli_sock->local.ip_addr;
    p_cli_sock->local.sock_addr.sin_port = htons(p_cli_sock->local.port);
}
#endif // TCP_CLI_CNNCT

#if (UDP_SVR_CNNCT == ENABLED)
static int32_t sock_open_udp_server(SOCK_INFO_T *p_svr_sock)
{
    int32_t flag;
    
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_svr_sock->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (p_svr_sock->sockfd < 0)
    {
        return ERROR_;
    }

    flag = 1;
    if (setsockopt(p_svr_sock->sockfd, SOL_SOCKET,  SO_REUSEADDR,  (char *)&flag, sizeof(int32_t)) < 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - SO_REUSEADDR\n");
        return ERROR_;
    }

    if (bind(p_svr_sock->sockfd, (struct sockaddr*)&p_svr_sock->local.sock_addr, sizeof(struct sockaddr_in)) < 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"bind failed\n");
        return ERROR_;
    }

    if (setsockopt(p_svr_sock->sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &p_svr_sock->local.mreq, sizeof(struct ip_mreq)) < 0) 
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - IP_ADD_MEMBERSHIP\n");
        return ERROR_;
    }
    
    DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"udp svr socket open - sockfd[%d]\n", p_svr_sock->sockfd);

    return 0;

}

static void sock_close_udp_server(SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx)
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    if (p_sock_cntx->udp_svr_sock[svr_idx].sockfd > 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"udp svr socket closed - sockfd[%d] \n", p_sock_cntx->udp_svr_sock[svr_idx].sockfd);
#if (USE_SOCK_SELECT == ENABLED)
        FD_CLR(p_sock_cntx->udp_svr_sock[svr_idx].sockfd, &p_sock_cntx->master_fd);
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
        sock_epoll_fd_del(p_sock_cntx, p_sock_cntx->udp_svr_sock[svr_idx].sockfd);
#endif // USE_SOCK_EPOLL

        close(p_sock_cntx->udp_svr_sock[svr_idx].sockfd);

        p_sock_cntx->udp_svr_sock[svr_idx].sockfd = -1;

        FREE_M(p_sock_cntx->udp_svr_sock[svr_idx].rbuf.buf);
        p_sock_cntx->udp_svr_sock[svr_idx].rbuf.buf_len = 0;
    }
}
#endif // UDP_SVR_CNNCT

#if (UDP_CLI_CNNCT == ENABLED)
static int32_t sock_open_udp_client(SOCK_INFO_T *p_cli_sock)
{
    int32_t flag;
    
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_cli_sock->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (p_cli_sock->sockfd < 0)
    {
        return ERROR_;
    }

    flag = 1;
    if (setsockopt(p_cli_sock->sockfd, SOL_SOCKET,  SO_REUSEADDR,  (char *)&flag, sizeof(int32_t)) < 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - SO_REUSEADDR\n");
        return ERROR_;
    }

    p_cli_sock->time_to_live = SOCK_MCAST_TTL;
    if (setsockopt(p_cli_sock->sockfd, IPPROTO_IP, IP_MULTICAST_TTL, (void*)&p_cli_sock->time_to_live, sizeof(int32_t)) < 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - IP_MULTICAST_TTL\n");
        return ERROR_;
    }

    {
        int optval;
        
        int optlen = sizeof(optval);
        
        getsockopt(p_cli_sock->sockfd, SOL_SOCKET, SO_RCVBUF, (char*)&optval, (socklen_t *)&optlen);

        DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"UDP CLI SO_RCVBUF = %d\n", optval);

        getsockopt(p_cli_sock->sockfd, SOL_SOCKET, SO_SNDBUF, (char*)&optval, (socklen_t *)&optlen);

        DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"UDP CLI SO_SNDBUF = %d\n", optval);
    }

    if (bind(p_cli_sock->sockfd, (struct sockaddr*)&p_cli_sock->local.sock_addr, sizeof(struct sockaddr_in)) < 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"bind failed\n");
        return ERROR_;
    }
    
    DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"udp cli socket open - sockfd[%d]\n", p_cli_sock->sockfd);

    return 0;

}

static void sock_close_udp_client(SOCK_CNTX_T *p_sock_cntx, int32_t cli_idx)
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    if (p_sock_cntx->udp_cli_sock[cli_idx].sockfd > 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"udp cli socket closed - sockfd[%d]\n", p_sock_cntx->udp_cli_sock[cli_idx].sockfd);
#if (USE_SOCK_SELECT == ENABLED)
        FD_CLR(p_sock_cntx->udp_cli_sock[cli_idx].sockfd, &p_sock_cntx->master_fd);
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
        sock_epoll_fd_del(p_sock_cntx, p_sock_cntx->udp_cli_sock[cli_idx].sockfd);
#endif // USE_SOCK_EPOLL

        close(p_sock_cntx->udp_cli_sock[cli_idx].sockfd);

        p_sock_cntx->udp_cli_sock[cli_idx].sockfd = -1;

        FREE_M(p_sock_cntx->udp_cli_sock[cli_idx].rbuf.buf);
        p_sock_cntx->udp_cli_sock[cli_idx].rbuf.buf_len = 0;
    }
}
#endif // UDP_CLI_CNNCT

#if (TCP_SVR_CNNCT == ENABLED)
int32_t sock_open_tcp_server(SOCK_INFO_T *p_svr_sock)
{
    int32_t flag;

    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    p_svr_sock->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    flag = 1;
    if (setsockopt(p_svr_sock->sockfd, SOL_SOCKET,  SO_REUSEADDR,  (char *)&flag, sizeof(int32_t)) < 0) // SO_LINGER TCP_NODELAY
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - SO_REUSEADDR\n");
        return ERROR_;
    }

    flag = 1;
    if (setsockopt(p_svr_sock->sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int32_t)) < 0) // SO_LINGER TCP_NODELAY
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - TCP_NODELAY\n");
        return ERROR_;
    }

    DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"TCP SVR LOCAL IP(%s) PORT(%d)\n", 
                    inet_ntoa(p_svr_sock->local.sock_addr.sin_addr), 
                    ntohs(p_svr_sock->local.sock_addr.sin_port));
    
    if (bind(p_svr_sock->sockfd, (struct sockaddr*)&p_svr_sock->local.sock_addr, sizeof(struct sockaddr_in)) < 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"bind failed\n");
        return ERROR_;
    }

    if (listen(p_svr_sock->sockfd, MAX_EVENTS) < 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"listen failed\n");
        return ERROR_;
    }

    DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"tcp svr socket open - sockfd[%d]\n", p_svr_sock->sockfd);

    return 0;
}

static void sock_close_tcp_server(SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx)
{
    //int32_t i = 0;

    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    if (p_sock_cntx->tcp_svr_sock[svr_idx].sockfd > 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"tcp svr socket closed - sockfd[%d]\n", p_sock_cntx->tcp_svr_sock[svr_idx].sockfd);
#if (USE_SOCK_SELECT == ENABLED)
        FD_CLR(p_sock_cntx->tcp_svr_sock[svr_idx].sockfd, &p_sock_cntx->master_fd);
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
        sock_epoll_fd_del(p_sock_cntx, p_sock_cntx->tcp_svr_sock[svr_idx].sockfd);
#endif // USE_SOCK_EPOLL

        close(p_sock_cntx->tcp_svr_sock[svr_idx].sockfd);

        p_sock_cntx->tcp_svr_sock[svr_idx].sockfd = -1;
        
        FREE_M(p_sock_cntx->tcp_svr_sock[svr_idx].rbuf.buf);
        p_sock_cntx->tcp_svr_sock[svr_idx].rbuf.buf_len = 0;

        sock_tcp_svr_usr_del_all(p_sock_cntx, svr_idx);
    }
}

void sock_tcp_usr_close (SOCK_CNTX_T *p_sock_cntx, int32_t sockfd, int32_t svr_idx)
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    if (sockfd <= 0)
    {
        ASSERT_M(0);
        return;
    }

    sock_tcp_svr_usr_del(p_sock_cntx, svr_idx, sockfd);
    p_sock_cntx->tcp_curr_sock_fd -= 1; 
}
#endif // TCP_SVR_CNNCT

#if (TCP_CLI_CNNCT == ENABLED)
static int32_t sock_open_tcp_client(SOCK_INFO_T *p_cli_sock)
{
    int32_t flag;
    
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"IP (%s) PORT(%d)\n", 
                    inet_ntoa(p_cli_sock->peer_svr.sock_addr.sin_addr), 
                    ntohs(p_cli_sock->peer_svr.sock_addr.sin_port));

    p_cli_sock->sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    flag = 1;
    if (setsockopt(p_cli_sock->sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int32_t)) < 0) // SO_LINGER TCP_NODELAY
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - TCP_NODELAY\n");
        return ERROR_;
    }
    {
        int optval;
        
        int optlen = sizeof(optval);
        
        getsockopt(p_cli_sock->sockfd, SOL_SOCKET, SO_RCVBUF, (char*)&optval, (socklen_t *)&optlen);

        DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"TCP CLI SO_RCVBUF = %d\n", optval);

        getsockopt(p_cli_sock->sockfd, SOL_SOCKET, SO_SNDBUF, (char*)&optval, (socklen_t *)&optlen);

        DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"TCP CLI SO_SNDBUF = %d\n", optval);
    }
#if 1
    if (bind(p_cli_sock->sockfd, (struct sockaddr*)&p_cli_sock->local.sock_addr, sizeof(struct sockaddr_in)) < 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"bind failed\n");
        return ERROR_;
    }
#endif
    if (connect(p_cli_sock->sockfd, (struct sockaddr*)&p_cli_sock->peer_svr.sock_addr, sizeof(struct sockaddr_in)) == ERROR_)
    {
        DBG_PRINT (DBG_SOCKET, DBG_ERROR, (void *)"connect failed\n");
        close(p_cli_sock->sockfd); // ?

        p_cli_sock->sockfd = -1;
        return ERROR_;
    }

    DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"tcp cli socket open - sockfd[%d]\n", p_cli_sock->sockfd);

    return 0;

}

void sock_close_tcp_client(SOCK_CNTX_T *p_sock_cntx, uint32_t sock_idx)
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    if (p_sock_cntx->tcp_cli_sock[sock_idx].sockfd > 0)
    {
        DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"socket closed - sockfd[%d]\n", p_sock_cntx->tcp_cli_sock[sock_idx].sockfd);

#if (USE_SOCK_SELECT == ENABLED)
        FD_CLR(p_sock_cntx->tcp_cli_sock[sock_idx].sockfd, &p_sock_cntx->master_fd);
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
        sock_epoll_fd_del(p_sock_cntx, p_sock_cntx->tcp_cli_sock[sock_idx].sockfd);
#endif // USE_SOCK_EPOLL

        close(p_sock_cntx->tcp_cli_sock[sock_idx].sockfd);

        p_sock_cntx->tcp_cli_sock[sock_idx].sockfd = -1;

        FREE_M(p_sock_cntx->tcp_cli_sock[sock_idx].rbuf.buf);
        p_sock_cntx->tcp_cli_sock[sock_idx].rbuf.buf_len = 0;
    }
}
#endif // TCP_CLI_CNNCT

//////////////////////////////////////////////////////////////////////////
// Global
#if (TCP_SVR_CNNCT == ENABLED)
static int32_t sock_tcp_svr_chk_my_peer_cli(SOCK_INFO_T *p_tcp_svr_sock, struct sockaddr_in *p_sock_addr)
{
    int32_t ret = ERROR_;
    uint32_t idx;

    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"client_addr(0x%08X) client_port(%d)\n", ntohl(p_sock_addr->sin_addr.s_addr), htons(p_sock_addr->sin_port));
    
    for(idx=0; idx<p_tcp_svr_sock->peer_cli_num; idx++)
    {
        DBG_PRINT(DBG_JSON, DBG_NONE, (void *)"TCP[%d] : peer_cli IP(0x%08X) PORT(%d)\n", 
                        idx, 
                        ntohl(p_tcp_svr_sock->peer_cli[idx].ip_addr), 
                        p_tcp_svr_sock->peer_cli[idx].port);

        if (   (p_tcp_svr_sock->peer_cli[idx].ip_addr == p_sock_addr->sin_addr.s_addr)
            && (p_tcp_svr_sock->peer_cli[idx].port == htons(p_sock_addr->sin_port)))
        {
            ret = SUCCESS_;
            break;
        }

    }

    return (ret);
}

void sock_tcp_svr_usr_init(SOCK_CNTX_T *p_sock_cntx)
{
    uint32_t idx, cnt;
    SOCK_TCP_USR_T *p_tcp_usr;
    SOCK_TCP_USR_ITEM_T *p_item;
    
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    for (idx=0; idx<p_sock_cntx->tcp_svr_num; idx++)
    {
        p_tcp_usr = &p_sock_cntx->tcp_usrs[idx];
        p_item = p_sock_cntx->tcp_usr_items[idx];

        list_init (&p_tcp_usr->tcp_usr_list);
        list_init (&p_tcp_usr->tcp_usr_pool);

        for( cnt=0; cnt<MAX_CLIENTS; cnt++ )
        {
            list_insert (&p_tcp_usr->tcp_usr_pool, &p_item[cnt].link);
        }
    }
}

int32_t sock_tcp_svr_usr_add(SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx, int32_t sockfd, struct sockaddr_in sock_addr)
{
    SOCK_TCP_USR_T *p_tcp_usr;
    SOCK_TCP_USR_ITEM_T *p_item;
    
    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_tcp_usr = &p_sock_cntx->tcp_usrs[svr_idx];
    if (list_is_empty(&p_tcp_usr->tcp_usr_pool))
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"tcp_usr_poll is Empty, svr_idx[%d]\n", svr_idx);
        return (ERROR_);
    }

    p_item = (SOCK_TCP_USR_ITEM_T *)list_remove(&p_tcp_usr->tcp_usr_pool);

    p_item->sockfd = sockfd;
    p_item->sock_addr = sock_addr;

    list_insert(&p_tcp_usr->tcp_usr_list, &p_item->link);

 //   if (svr_idx != TCP_SVR_2)
 //   {
#if (USE_SOCK_SELECT== ENABLED)
        sock_init_fd(p_sock_cntx, sockfd);  
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
        sock_epoll_fd_add(p_sock_cntx, sockfd);
#endif // USE_SOCK_EPOLL
 //   }

    return (SUCCESS_);
}

SOCK_TCP_USR_ITEM_T *sock_tcp_svr_usr_search(LIST_T *p_list, int32_t sockfd)
{
    LIST_ITEM_T *p_item;
    SOCK_TCP_USR_ITEM_T *p_tcp_usr_item;
    int32_t num;

    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"(%s)\n", __FUNCTION__);
    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"sockfd (%d)\n", sockfd);
    
    num = list_get_num_of_list(p_list);

    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"(%s)\n", num);

    if( p_list->num_items == 0 )
    {
        return (NULL);
    }

    p_item = p_list->head;

    while (p_item)
    {
        p_tcp_usr_item = (SOCK_TCP_USR_ITEM_T *)p_item;
        if (p_tcp_usr_item->sockfd == sockfd)
        {
            return (p_tcp_usr_item);
        }
        
        p_item = p_item->next;
    }

    return (NULL);
}

void sock_tcp_svr_usr_debug(LIST_T *p_list)
{
    LIST_ITEM_T *p_item;
    SOCK_TCP_USR_ITEM_T *p_tcp_usr_item;
    int32_t num;

    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"num_items (%d)\n", p_list->num_items);
    
    num = list_get_num_of_list(p_list);

    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"(%s)\n", num);

    if( p_list->num_items == 0 )
    {
        return;
    }

    p_item = p_list->head;

    while (p_item)
    {
        p_tcp_usr_item = (SOCK_TCP_USR_ITEM_T *)p_item;

        DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"sockfd (%d)\n", p_tcp_usr_item->sockfd);
        
        p_item = p_item->next;
    }
}

int32_t sock_tcp_svr_usr_del(SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx, int32_t sockfd)
{
    SOCK_TCP_USR_T *p_tcp_usr;

    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_tcp_usr = &p_sock_cntx->tcp_usrs[svr_idx];
    
    if (!list_is_empty(&p_tcp_usr->tcp_usr_list))
    {
        SOCK_TCP_USR_ITEM_T *p_item;

        p_item = sock_tcp_svr_usr_search(&p_tcp_usr->tcp_usr_list, sockfd);
        if (p_item)
        {
            list_remove_item(&p_tcp_usr->tcp_usr_list, &p_item->link);

            p_item->sockfd = -1;
            FREE_M(p_item->rbuf.buf);
            p_item->rbuf.buf_len = 0;
            
            DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"tcp svr socket closed - svr_idx[%d] sockfd[%d] list(%d)\n", svr_idx, sockfd, list_is_empty(&p_tcp_usr->tcp_usr_list));
#if (USE_SOCK_SELECT == ENABLED)
            FD_CLR(sockfd, &p_sock_cntx->master_fd);
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
            sock_epoll_fd_del(p_sock_cntx, sockfd);
#endif // USE_SOCK_EPOLL

            close(sockfd);

            // Return the list into POOL
            list_insert(&p_tcp_usr->tcp_usr_pool, &p_item->link);

            //sock_tcp_svr_usr_debug(&p_tcp_usr->tcp_usr_list);
            //ASSERT_M(0);

            return (SUCCESS_);
        }
    }

    return (ERROR_);
}

int32_t sock_tcp_svr_usr_del_all(SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx)
{
    SOCK_TCP_USR_T *p_tcp_usr;

    DBG_PRINT(DBG_TASK, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    p_tcp_usr = &p_sock_cntx->tcp_usrs[svr_idx];
    
    while (!list_is_empty(&p_tcp_usr->tcp_usr_list))
    {
        SOCK_TCP_USR_ITEM_T *p_item;
        
        // Get the item from LIST
        p_item = (SOCK_TCP_USR_ITEM_T *)list_remove(&p_tcp_usr->tcp_usr_list);

        DBG_PRINT (DBG_SOCKET, DBG_INFO, (void *)"tcp svr socket closed - svr_idx[%d] sockfd[%d]\n", svr_idx, p_item->sockfd);
#if (USE_SOCK_SELECT == ENABLED)
        FD_CLR(p_item->sockfd, &p_sock_cntx->master_fd);
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
        sock_epoll_fd_del(p_sock_cntx, p_item->sockfd);
#endif // USE_SOCK_EPOLL

        close(p_item->sockfd);

        p_item->sockfd = -1;

        FREE_M(p_item->rbuf.buf);
        p_item->rbuf.buf_len = 0;

        // Return the list into POOL
        list_insert(&p_tcp_usr->tcp_usr_pool, &p_item->link);
    }

    return (ERROR_);
}
#endif // TCP_SVR_CNNCT

void sock_update (SOCK_CNTX_T *p_sock_cntx) 
{
    uint32_t sock_idx;

    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    json_socket_udpate(p_sock_cntx);

#if (UDP_SVR_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->udp_svr_num; sock_idx++)
    {
        sock_init_udp_server(&p_sock_cntx->udp_svr_sock[sock_idx]);
    }
#endif // UDP_SVR_CNNCT

#if (UDP_CLI_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->udp_cli_num; sock_idx++)
    {
        sock_init_udp_client(&p_sock_cntx->udp_cli_sock[sock_idx]);
    }
#endif // UDP_CLI_CNNCT

#if (TCP_SVR_CNNCT == ENABLED)
    sock_tcp_svr_usr_init(p_sock_cntx);

    for (sock_idx=0; sock_idx<p_sock_cntx->tcp_svr_num; sock_idx++)
    {
        sock_init_tcp_server(&p_sock_cntx->tcp_svr_sock[sock_idx]);
    }
#endif // TCP_SVR_CNNCT

#if (TCP_CLI_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->tcp_cli_num; sock_idx++)
    {
        sock_init_tcp_client(&p_sock_cntx->tcp_cli_sock[sock_idx]);
    }
#endif // TCP_CLI_CNNCT
}

void sock_init (SOCK_CNTX_T *p_sock_cntx, bool b_init) 
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    if (b_init)
    {
    MEMSET_M(p_sock_cntx, 0, sizeof(SOCK_CNTX_T));

    // Init
#if (USE_SOCK_SELECT == ENABLED)
    FD_ZERO(&p_sock_cntx->master_fd);
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
    sock_create_epoll(p_sock_cntx);
#endif // USE_SOCK_EPOLL
    }

    sock_update(p_sock_cntx);
}

#if (USE_SOCK_SELECT == ENABLED)
void sock_init_fd(SOCK_CNTX_T *p_sock_cntx, int32_t sockfd)
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    // Init fd
    FD_SET(sockfd, &p_sock_cntx->master_fd);
    p_sock_cntx->master_fd_max = sockfd + 1;
}
#endif //USE_SOCK_SELECT

int32_t sock_open_server_proc(SOCK_CNTX_T *p_sock_cntx)
{
    int32_t ret;
    uint32_t sock_idx;

    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

#if (UDP_SVR_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->udp_svr_num; sock_idx++)
    {
        ret = sock_open_udp_server(&p_sock_cntx->udp_svr_sock[sock_idx]);
        if (ret < 0)
        {
            return (ret);
        }

#if (USE_SOCK_SELECT == ENABLED)
        sock_init_fd(p_sock_cntx, p_sock_cntx->udp_svr_sock[sock_idx].sockfd);
#endif // USE_SOCK_SELECT
#if (USE_SOCK_EPOLL == ENABLED)
        sock_epoll_fd_add(p_sock_cntx, p_sock_cntx->udp_svr_sock[sock_idx].sockfd);
#endif // USE_SOCK_EPOLL
    }
#endif // UDP_SVR_CNNCT

//
#if (TCP_SVR_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->tcp_svr_num; sock_idx++)
    {
        ret = sock_open_tcp_server(&p_sock_cntx->tcp_svr_sock[sock_idx]);
        if (ret < 0)
        {
            return (ret);
        }
        
#if (USE_SOCK_SELECT == ENABLED)
        sock_init_fd(p_sock_cntx, p_sock_cntx->tcp_svr_sock[sock_idx].sockfd);
#endif // USE_SOCK_SELECT
#if (USE_SOCK_EPOLL == ENABLED)
        sock_epoll_fd_add(p_sock_cntx, p_sock_cntx->tcp_svr_sock[sock_idx].sockfd);
#endif // USE_SOCK_EPOLL
    }
#endif // TCP_SVR_CNNCT

    return (SUCCESS_);
}

int32_t sock_open_udp_client_proc(SOCK_CNTX_T *p_sock_cntx)
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
#if (UDP_CLI_CNNCT == ENABLED)
    int32_t ret;
    uint32_t sock_idx;
    
    for (sock_idx=0; sock_idx<p_sock_cntx->udp_cli_num; sock_idx++)
    {
        ret = sock_open_udp_client(&p_sock_cntx->udp_cli_sock[sock_idx]);
        if (ret < 0)
        {
            return (ret);
        }

#if (USE_SOCK_SELECT == ENABLED)
        sock_init_fd(p_sock_cntx, p_sock_cntx->udp_cli_sock[sock_idx].sockfd);
#endif // USE_SOCK_SELECT
#if (USE_SOCK_EPOLL == ENABLED)
        sock_epoll_fd_add(p_sock_cntx, p_sock_cntx->udp_cli_sock[sock_idx].sockfd);
#endif // USE_SOCK_EPOLL
    }
#endif // UDP_CLI_CNNCT

    return (SUCCESS_);
}

int32_t sock_open_tcp_client_proc(SOCK_CNTX_T *p_sock_cntx)
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
#if (TCP_CLI_CNNCT == ENABLED)
    int32_t ret;
    uint32_t sock_idx;
    SOCK_INFO_T *p_cli_cntx;
    
    for (sock_idx=0; sock_idx<p_sock_cntx->tcp_cli_num; sock_idx++)
    {
        p_cli_cntx = &p_sock_cntx->tcp_cli_sock[sock_idx];
        
        if (p_cli_cntx->auto_join)
        {
            ret = sock_open_tcp_client(p_cli_cntx);
            if (ret < 0)
            {
                timer_sw_reg((uint8_t *)"p2p_sc1", true, 1000000, 0, p2p_timer_sock_conn, sock_idx);
                //timer_sw_reg((uint8_t *)"p2p_sc1", true, 1000000, 0, p2p_timer_sock_conn_with_idx, sock_idx);
                
                continue;
                //return (ret);
            }

#if (USE_SOCK_SELECT == ENABLED)
            sock_init_fd(p_sock_cntx, p_cli_cntx->sockfd);
#endif // USE_SOCK_SELECT
#if (USE_SOCK_EPOLL == ENABLED)
            sock_epoll_fd_add(p_sock_cntx, p_cli_cntx->sockfd);
#endif // USE_SOCK_EPOLL

#if (SOCK_REJOIN == DISABLED)
            p_cli_cntx->auto_join = false;
#endif // SOCK_REJOIN
            if (p_cli_cntx->p2p_join)
            {
                p2p_tcp_client_join_proc(p_sock_cntx, sock_idx);
            }
        }
    }
#endif // TCP_CLI_CNNCT

    return (SUCCESS_);
}

int32_t sock_open_tcp_client_with_reinit(SOCK_CNTX_T *p_sock_cntx, uint32_t sock_idx, char *p_peer_ip_str, uint32_t peer_ip, uint16_t peer_port)
{
    SOCK_INFO_T *p_cli_cntx = &p_sock_cntx->tcp_cli_sock[sock_idx];

    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    sock_close_tcp_client(p_sock_cntx, sock_idx);

    p_cli_cntx->peer_svr.sock_addr.sin_family=AF_INET;
    if (p_peer_ip_str)
    {
        p_cli_cntx->peer_svr.sock_addr.sin_addr.s_addr = inet_addr((char *) p_peer_ip_str);
    }
    else
    {
        p_cli_cntx->peer_svr.sock_addr.sin_addr.s_addr = peer_ip;
    }
    p_cli_cntx->peer_svr.sock_addr.sin_port = htons(peer_port);

    timer_sw_reg((uint8_t *)"p2p_sc3", true, 10000, 0, p2p_timer_sock_conn_with_idx, sock_idx);

    return (SUCCESS_);
}

int32_t sock_open_tcp_client_with_reopen(SOCK_CNTX_T *p_sock_cntx, uint32_t sock_idx)
{
    int32_t ret;
    SOCK_INFO_T *p_cli_cntx = &p_sock_cntx->tcp_cli_sock[sock_idx];

    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    ret = sock_open_tcp_client(p_cli_cntx);
    if (ret < 0)
    {
        timer_sw_reg((uint8_t *)"p2p_sc2", true, 1000000, 0, p2p_timer_sock_conn_with_idx, sock_idx);
        return (ERROR_);
    }

#if (USE_SOCK_SELECT == ENABLED)
    sock_init_fd(p_sock_cntx, p_cli_cntx->sockfd);
#endif // USE_SOCK_SELECT
#if (USE_SOCK_EPOLL == ENABLED)
    sock_epoll_fd_add(p_sock_cntx, p_cli_cntx->sockfd);
#endif // USE_SOCK_EPOLL

    if (p_cli_cntx->p2p_join)
    {
        p2p_tcp_client_join_proc(p_sock_cntx, sock_idx);
    }

    return (SUCCESS_);
}

void sock_close (SOCK_CNTX_T *p_sock_cntx)
{
    uint32_t sock_idx;

    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

#if (UDP_CLI_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->udp_cli_num; sock_idx++)
    {
        sock_close_udp_client(p_sock_cntx, sock_idx);
    }
#endif // UDP_CLI_CNNCT

#if (UDP_SVR_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->udp_svr_num; sock_idx++)
    {
        sock_close_udp_server(p_sock_cntx, sock_idx);
    }
#endif // UDP_SVR_CNNCT

#if (TCP_CLI_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->tcp_cli_num; sock_idx++)
    {
        sock_close_tcp_client(p_sock_cntx, sock_idx);
    }
#endif // TCP_CLI_CNNCT

#if (TCP_SVR_CNNCT == ENABLED)
    for (sock_idx=0; sock_idx<p_sock_cntx->tcp_svr_num; sock_idx++)
    {
        sock_close_tcp_server(p_sock_cntx, sock_idx);
    }
#endif // TCP_SVR_CNNCT
}

void sock_delete (SOCK_CNTX_T *p_sock_cntx)
{
    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

#if (UDP_CLI_CNNCT == ENABLED)
    p_sock_cntx->udp_cli_num = 0;
    MEMSET_M(p_sock_cntx->udp_cli_sock, 0x00, sizeof(SOCK_INFO_T)*UDP_CLI_MAX);
#endif // UDP_CLI_CNNCT

#if (UDP_SVR_CNNCT == ENABLED)
    p_sock_cntx->udp_svr_num = 0;
    MEMSET_M(p_sock_cntx->udp_svr_sock, 0x00, sizeof(SOCK_INFO_T)*UDP_SVR_MAX);
#endif // UDP_SVR_CNNCT

#if (TCP_CLI_CNNCT == ENABLED)
    p_sock_cntx->tcp_cli_num = 0;
    MEMSET_M(p_sock_cntx->tcp_cli_sock, 0x00, sizeof(SOCK_INFO_T)*TCP_CLI_MAX);
#endif // TCP_CLI_CNNCT

#if (TCP_SVR_CNNCT == ENABLED)
    p_sock_cntx->tcp_svr_num = 0;
    MEMSET_M(p_sock_cntx->tcp_svr_sock, 0x00, sizeof(SOCK_INFO_T)*TCP_SVR_MAX);
#endif // TCP_SVR_CNNCT
}

int sock_fd_wait(SOCK_CNTX_T *p_sock_cntx)
{
    int32_t ret;
    
#if (USE_SOCK_SELECT == ENABLED)
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    
    p_sock_cntx->event_fd = p_sock_cntx->master_fd;
    ret = select(p_sock_cntx->master_fd_max, &p_sock_cntx->event_fd, 0, 0, &tv);
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
    ret = epoll_wait(p_sock_cntx->epoll_fd, p_sock_cntx->events, MAX_EVENTS, 0);
#endif // USE_SOCK_EPOLL

    return (ret);
}


#if (TCP_SVR_CNNCT == ENABLED)
int32_t sock_usr_set_opt_keep_alive(int32_t sockfd)
{
    int32_t flag, ret;

    flag = 1;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
    if(ret < 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - SO_KEEPALIVE\n");
        return (ret);
    }
#if 0
    flag = 1;
    ret = setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, &flag, sizeof(flag));
    if(ret < 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - SO_KEEPALIVE\n");
        return (ret);
    }

    flag = 1;
    ret = setsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, &flag, sizeof(flag));
    if(ret < 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - TCP_KEEPCNT\n");
        return (ret);
    }

    flag = 1;
    ret = setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, &flag, sizeof(flag));
    if(ret < 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - TCP_KEEPINTVL\n");
        return (ret);
    }
#endif
    return (ret);
}

int32_t sock_usr_set_opt_defalt(int32_t sockfd)
{
    int32_t flag;
    struct linger ling = {1, 0};

    DBG_PRINT (DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    flag = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int32_t)) < 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - TCP_NODELAY\n");
        return ERROR_;
    }
    
    flag = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling)) < 0)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"setsocket option error - SO_LINGER\n");
        return ERROR_;
    }

    {
        int optval;
        
        int optlen = sizeof(optval);
        
        getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char*)&optval, (socklen_t *)&optlen);

        DBG_PRINT (DBG_SOCKET, DBG_NONE, (void *)"TCP SVR USR SO_RCVBUF = %d\n", optval);

        getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char*)&optval, (socklen_t *)&optlen);

        DBG_PRINT (DBG_SOCKET, DBG_NONE, (void *)"TCP SVR USR SO_SNDBUF = %d\n", optval);
    }
    return (SUCCESS_);
}

int32_t sock_process_usr_accept (SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx)
{
    int32_t ret;
    int32_t sk_addr_len = 0; 
    struct sockaddr_in sock_addr;
    int32_t client_fd;

    DBG_PRINT(DBG_SOCKET, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    sk_addr_len = sizeof(sock_addr);
    client_fd = accept(p_sock_cntx->tcp_svr_sock[svr_idx].sockfd, (struct sockaddr *)&sock_addr, (socklen_t *)&sk_addr_len);
    if (client_fd == -1)
    {
        DBG_PRINT(DBG_SOCKET, DBG_ERROR, (void *)"accept failed\n");
        return (ERROR_);
    }
    
    if(sock_usr_set_opt_defalt(client_fd) < 0)
    {
        return (ERROR_);
    }

    if(sock_usr_set_opt_keep_alive(client_fd) < 0)
    {
        return (ERROR_);
    }
    
    DBG_PRINT(DBG_SOCKET, DBG_NONE, (void *)"client_fd(%d) client_addr(0x%08X) client_port(%d)\n", client_fd, ntohl(sock_addr.sin_addr.s_addr), htons(sock_addr.sin_port));
    ret = sock_tcp_svr_chk_my_peer_cli(&p_sock_cntx->tcp_svr_sock[svr_idx], &sock_addr);
    if (ret == ERROR_)
    {
        //ASSERT_M(0);
        close(client_fd);
        return (ERROR_);
    }

    ret = sock_tcp_svr_usr_add(p_sock_cntx, svr_idx, client_fd, sock_addr);
    if (ret == ERROR_)
    {
        ASSERT_M(0);
        sock_tcp_usr_close(p_sock_cntx, client_fd, svr_idx);

        return (ERROR_);
    }
    
#if (USE_SOCK_SELECT== ENABLED)
    DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"master_fd_max(%d)\n", p_sock_cntx->master_fd_max);
    DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"master_fd(0x%08X)\n", p_sock_cntx->master_fd);
#endif // USE_SOCK_SELECT

    return (SUCCESS_);
}
#endif  // TCP_SVR_CNNCT

int32_t sock_send_data (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, uint8_t *p_buf, uint32_t len)
{
    int32_t ret;

    if (p_peer_sock_addr) // UDP
    {
#if ((UDP_CLI_CNNCT == ENABLED) || (UDP_SVR_CNNCT == ENABLED))
        DBG_PRINT(DBG_SOCKET, DBG_INFO, (void *)"dst s_addr(0x%08X)\n", p_peer_sock_addr->sin_addr.s_addr);
        
        ret = sendto(sockfd, p_buf, len, 0, ( struct sockaddr*)p_peer_sock_addr, sizeof(struct sockaddr_in)); 
#endif // UDP_CLI_CNNCT
    }
    else // TCP
    {
#if ((TCP_CLI_CNNCT == ENABLED) || (TCP_SVR_CNNCT == ENABLED))
        ret = write(sockfd, p_buf, len);
#endif // TCP_CLI_CNNCT
    }
    
    return (ret);
}

