/**
    @file timer.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __TIMER_H__
#define __TIMER_H__

#ifdef __cplusplus
extern "C"
{
#endif

#define TIMER_EXE ENABLED // ENABLED, DISABLED
#define TIMER_TEST DISABLED // ENABLED, DISABLED

#define TIMER_LIST_CHANGED 1

typedef int32_t (*_timer_cb)(int32_t in_val_1);

typedef struct TIMER_SW {
    uint8_t name[16];
    bool one_shot;
    uint32_t tick; // MAX 1 year
    uint32_t usec;
    uint64_t utc_usec;

    _timer_cb timer_cb;
    int32_t in_val_1;

    struct TIMER_SW *next;
} __attribute__((__packed__)) TIMER_SW_T;

extern void timer_init (void);
extern int32_t timer_start (timer_t *p_timer_id, uint32_t usec);
extern void timer_stop(timer_t timer_id);

extern uint32_t timer_get_resol_usec(void);
extern void timer_trace (void);

extern int32_t timer_sw_reg(uint8_t *p_name, bool one_shot, uint32_t usec, uint64_t utc_usec, _timer_cb timer_cb, int32_t in_val_1);
extern int32_t timer_sw_dereg_by_name(uint8_t *p_name);
extern int32_t timer_sw_dereg(TIMER_SW_T *p_del_tm);

extern int32_t timer_change_tick_by_name(uint8_t *p_name);

#if (TIMER_TEST == ENABLED)
extern void timer_run_test (void);
#endif // SEC_TIMER_TEST

#ifdef __cplusplus
}
#endif

#endif /* __TIMER_H__ */

