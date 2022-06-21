/**
    @file p2p_timer.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __P2P_TIMER_H__
#define __P2P_TIMER_H__

#ifdef __cplusplus
extern "C"
{
#endif

// Socket Connection Timer (oneshot)
extern int32_t p2p_timer_sock_conn(int32_t in_val_1);
extern int32_t p2p_timer_sock_conn_with_idx(int32_t in_val_1);

extern void p2p_timer_run (void);

#ifdef __cplusplus
}
#endif

#endif /* __P2P_TIMER_H__ */

