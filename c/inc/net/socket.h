/**
    @file socket.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __SOCKET_H__
#define __SOCKET_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define USE_SOCK_SELECT DISABLED // ENABLED DISABLED
#define USE_SOCK_EPOLL  ENABLED // ENABLED DISABLED

#define UDP_CLI_CNNCT   ENABLED // ENABLED DISABLED
#define UDP_SVR_CNNCT   ENABLED // ENABLED DISABLED
#define TCP_CLI_CNNCT   ENABLED // ENABLED DISABLED
#define TCP_SVR_CNNCT   ENABLED // ENABLED DISABLED

#define SOCK_FIREWALLD  DISABLED // ENABLED DISABLED
#define SOCK_REJOIN     DISABLED // ENABLED DISABLED

#define TCP_SVR_1   0
#define TCP_SVR_2   1
#define TCP_SVR_3   2
#define TCP_SVR_MAX 3

#define TCP_CLI_1   0
#define TCP_CLI_2   1
#define TCP_CLI_MAX 2

#define UDP_SVR_1   0
#define UDP_SVR_2   1
#define UDP_SVR_MAX 2

#define UDP_CLI_1   0
#define UDP_CLI_2   1
#define UDP_CLI_MAX 2

#define MAX_EVENTS  10000
#if (TCP_SVR_CNNCT == ENABLED)
#define MAX_CLIENTS MAX_EVENTS
#endif // TCP_SVR_CNNCT

#define SOCK_ADDR_MAX 21

#define SOCK_PKT_DEFAULT_LEN 1024
#define SOCK_CFM_PKT_LEN 1600 // (x*int32_t)
#define SOCK_CFM_BUF_LEN (SOCK_PKT_DEFAULT_LEN*300) // (1024*160 = 163840) (1024*208 = 212992)

#define SOCK_ADDR_NULL 0

#define SOCK_MCAST_TTL 64

typedef struct
{
    uint16_t priv_seq_num;
    uint16_t rsvd;
    uint32_t buf_len;
    uint8_t *buf;
    //uint8_t buf[SOCK_CFM_PKT_LEN];
} SOCK_RCV_BUF_T;

typedef struct
{
    struct ip_mreq mreq;
    struct sockaddr_in sock_addr;

    // Initial value
    in_addr_t mreq_ip_addr;
    in_addr_t ip_addr; // inet_addr("127.0.0.1"); // htonl(INADDR_ANY) = inet_addr("0.0.0.0");
    uint16_t port;
    uint16_t rsvd;
} SOCK_INFO_SUB_T;

typedef struct
{
    int32_t sockfd;
    int32_t time_to_live;
    int32_t auto_join;
    int32_t p2p_join; // Actually, it's P2P layer issue.

    uint32_t peer_cli_num;
    SOCK_INFO_SUB_T peer_cli[SOCK_ADDR_MAX];
    SOCK_INFO_SUB_T peer_svr;
    SOCK_INFO_SUB_T local;

    uint16_t my_p2p_data_sn;
    uint16_t my_p2p_cmd_sn;

    SOCK_RCV_BUF_T rbuf;
} SOCK_INFO_T;

typedef struct
{
    struct timeval tv;
    struct timespec ts;
    sigset_t sigs;
} SOCK_TIMER_T;

#if (TCP_SVR_CNNCT == ENABLED)
typedef struct
{
    LIST_T tcp_usr_list;
    LIST_T tcp_usr_pool;
} SOCK_TCP_USR_T;

typedef struct
{
    LIST_ITEM_T   link;
    int32_t sockfd;
    struct sockaddr_in sock_addr;

    uint16_t my_p2p_data_sn;
    uint16_t my_p2p_cmd_sn;
    
    SOCK_RCV_BUF_T rbuf;
} SOCK_TCP_USR_ITEM_T;
#endif // TCP_SVR_CNNCT

typedef struct 
{
#if (USE_SOCK_SELECT == ENABLED)
    fd_set event_fd; // readfd
    fd_set master_fd;
    int32_t master_fd_max;
#endif // USE_SOCK_SELECT

#if (USE_SOCK_EPOLL == ENABLED)
    epoll_event events[MAX_EVENTS];
    int32_t epoll_fd;
#endif // USE_SOCK_EPOLL

#if (UDP_CLI_CNNCT == ENABLED)
    uint32_t udp_cli_num;
    SOCK_INFO_T udp_cli_sock[UDP_CLI_MAX];
#endif // UDP_CLI_CNNCT

#if (UDP_SVR_CNNCT == ENABLED)
    uint32_t udp_svr_num;
    SOCK_INFO_T udp_svr_sock[UDP_SVR_MAX];
#endif // UDP_SVR_CNNCT

#if (TCP_CLI_CNNCT == ENABLED)
    uint32_t tcp_cli_num;
    SOCK_INFO_T tcp_cli_sock[TCP_CLI_MAX];
#endif // TCP_CLI_CNNCT

#if (TCP_SVR_CNNCT == ENABLED)
    uint32_t tcp_svr_num;
    SOCK_INFO_T tcp_svr_sock[TCP_SVR_MAX];

    SOCK_TCP_USR_T tcp_usrs[TCP_SVR_MAX];
    SOCK_TCP_USR_ITEM_T tcp_usr_items[TCP_SVR_MAX][MAX_CLIENTS];
    
    int32_t tcp_curr_sock_fd;
    SOCK_RCV_BUF_T *tcp_curr_rbuf;
#endif // TCP_SVR_CNNCT

    uint8_t rcv_buf[SOCK_CFM_BUF_LEN];
} SOCK_CNTX_T;

#if (TCP_SVR_CNNCT == ENABLED)
extern void sock_tcp_svr_usr_init(SOCK_CNTX_T *p_sock_cntx);
extern int32_t sock_tcp_svr_usr_add(SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx, int32_t sockfd, struct sockaddr_in sock_addr);
extern SOCK_TCP_USR_ITEM_T *sock_tcp_svr_usr_search(LIST_T *p_list, int32_t sockfd);
extern void sock_tcp_svr_usr_debug(LIST_T *p_list);
extern int32_t sock_tcp_svr_usr_del(SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx, int32_t sockfd);
extern int32_t sock_tcp_svr_usr_del_all(SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx);
#endif // TCP_SVR_CNNCT

extern void sock_init (SOCK_CNTX_T *p_sock_cntx, bool b_init);

extern int32_t sock_open_server_proc(SOCK_CNTX_T *p_sock_cntx);
extern int32_t sock_open_udp_client_proc(SOCK_CNTX_T *p_sock_cntx);
extern int32_t sock_open_tcp_client_proc(SOCK_CNTX_T *p_sock_cntx);
extern int32_t sock_open_tcp_client_with_reinit(SOCK_CNTX_T *p_sock_cntx, uint32_t sock_idx, char *p_peer_ip_str, uint32_t peer_ip, uint16_t peexer_port);
extern int32_t sock_open_tcp_client_with_reopen(SOCK_CNTX_T *p_sock_cntx, uint32_t sock_idx);
extern void sock_close (SOCK_CNTX_T *p_sock_cntx);
extern void sock_delete (SOCK_CNTX_T *p_sock_cntx);
extern int sock_fd_wait(SOCK_CNTX_T *p_sock_cntx);

#if (TCP_CLI_CNNCT == ENABLED)
extern void sock_close_tcp_client(SOCK_CNTX_T *p_sock_cntx, uint32_t sock_idx);
#endif // TCP_CLI_CNNCT

#if (TCP_SVR_CNNCT == ENABLED)
extern void sock_tcp_usr_close (SOCK_CNTX_T *p_sock_cntx, int32_t sockfd, int32_t svr_idx);
extern int32_t sock_process_usr_accept (SOCK_CNTX_T *p_sock_cntx, int32_t svr_idx);
#endif  // TCP_SVR_CNNCT
extern int32_t sock_send_data (int32_t sockfd, struct sockaddr_in *p_peer_sock_addr, uint8_t *p_buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* __SOCKET_H__ */

