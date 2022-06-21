/**
    @file p2p_sock.h
    @date2018/11/15
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __P2P_SOCK_H__
#define __P2P_SOCK_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define P2P_PKT_IND_SEPARATED DISABLED // ENABLED DISABLED

typedef enum
{
    P2P_SOCK_EVT_SUCCESS,
    P2P_SOCK_EVT_ERROR,
    P2P_SOCK_EVT_NONE,
#if (TCP_CLI_CNNCT == ENABLED)
    P2P_SOCK_EVT_TCP_CLI_IND,
#endif // TCP_CLI_CNNCT
#if (UDP_CLI_CNNCT == ENABLED)
   P2P_SOCK_EVT_UDP_CLI_IND,
#endif // UDP_CLI_CNNCT
#if (TCP_SVR_CNNCT == ENABLED)
    P2P_SOCK_EVT_TCP_SVR_USER_ACCEPT,
    P2P_SOCK_EVT_TCP_SVR_USER_IND,
#endif // TCP_SVR_CNNCT
#if (UDP_SVR_CNNCT == ENABLED)
    P2P_SOCK_EVT_UDP_SVR_USER_IND,
#endif // TCP_SVR_CNNCT

    P2P_SOCK_EVT_MAX
} P2P_SOCK_EVT_E;

extern int32_t p2p_sock_pkt_ind(int32_t rx_sockfd, struct sockaddr_in *p_peer_sock_addr, P2P_SRVC_IND_T *p_msg);

extern SOCK_CNTX_T *p2p_sock_cntx(void);
extern void p2p_sock_init(bool b_init);
extern int32_t p2p_sock_event_handler (void);

#ifdef __cplusplus
}
#endif

#endif /* __P2P_SOCK_H__ */

