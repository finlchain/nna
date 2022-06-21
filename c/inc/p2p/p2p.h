/**
    @file p2p.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __P2P_H__
#define __P2P_H__

#ifdef __cplusplus
extern "C"
{
#endif

extern void p2p_task_init(void);
extern void *t_p2p_main(void *p_data);

extern void p2p_init(bool b_init);
extern P2P_CNTX_T *p2p_get_cntx(void);

#if (P2P_TEST == ENABLED)
extern void p2p_data_client_test(void);
#endif // P2P_TEST

//
extern void p2p_send_join_req(int32_t sockfd);

//
extern void p2p_tcp_client_join_proc(SOCK_CNTX_T *p_sock_cntx, uint32_t sock_idx);

#ifdef __cplusplus
}
#endif

#endif /* __P2P_H__ */

