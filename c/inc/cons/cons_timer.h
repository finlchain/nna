/**
    @file cons_timer.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __CONS_TIMER_H__
#define __CONS_TIMER_H__

#ifdef __cplusplus
extern "C"
{
#endif

extern int32_t cons_fsdump_temp(int32_t in_val_1);
extern int32_t cons_timer_tx_stop(int32_t in_val_1);

extern void cons_timer_run (void);

#ifdef __cplusplus
}
#endif

#endif /* __CONS_TIMER_H__ */

