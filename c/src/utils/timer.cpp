/**
    @file timer.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#define TIMER_RESOLUTION_USEC 10000

typedef struct __list {
    struct TIMER_SW *cur;
    struct TIMER_SW *head;
    struct TIMER_SW *tail;
} timer_linked_list; 

static timer_linked_list *gp_linked_list = NULL;

pthread_mutex_t timer_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint32_t g_resol_usec = 0;
static uint32_t g_sw_tm_cnt = 0;

#if (TIMER_EXE == ENABLED)
timer_t g_timer_id;
#endif // TIMER_EXE

int32_t timer_sw_exe (void);

void timer_linked_list_init(void)
{
    timer_linked_list *L;
    
    // linked_list pointer define start 
    gp_linked_list = (timer_linked_list *)MALLOC_M(sizeof(timer_linked_list));

    L = gp_linked_list;

    L->cur = NULL;
    L->head = NULL;
    L->tail = NULL;
}

void timer_init(void)
{
    int32_t ret;
    
    g_resol_usec = 0;
    g_sw_tm_cnt = 0;
    
    timer_linked_list_init();

#if (TIMER_EXE == ENABLED)
    ret = timer_start(&g_timer_id, TIMER_RESOLUTION_USEC);
    if (ret == ERROR_)
    {
        ASSERT_M(0);
    }
#endif // TIMER_EXE
}

void timer_handler  (int signum)
//void timer_handler( int sig, siginfo_t *si, void *uc )
{
    //static int count = 0;
    int32_t ret;

    //DBG_PRINT(DBG_TIMER, DBG_INFO, (void *)"timer expired %u timers\n", ++count);

    do
    {
        ret = timer_sw_exe();
    } while (ret == TIMER_LIST_CHANGED);
}

int32_t timer_start (timer_t *p_timer_id, uint32_t usec)
{
#if 1
    struct itimerspec value;
    struct sigevent av_sig_spec;

    if (!p_timer_id)
    {
        return (ERROR_);
    }

    MEMSET_M(&av_sig_spec, 0x00, sizeof(struct sigevent));
    av_sig_spec.sigev_notify = SIGEV_SIGNAL;
    av_sig_spec.sigev_signo = SIGRTMIN;

    value.it_value.tv_sec = 0;
    value.it_value.tv_nsec = usec*1000;
    value.it_interval.tv_sec = 0;
    value.it_interval.tv_nsec = usec*1000;

    timer_create(CLOCK_REALTIME, &av_sig_spec, p_timer_id);

    timer_settime(*p_timer_id, 0, &value, NULL);
    signal(SIGRTMIN, timer_handler);
#else
    struct sigevent te;
    struct itimerspec its;
    struct sigaction sa;
    int sigNo = SIGRTMIN;

    if (!p_timer_id)
    {
        return (ERROR_);
    }

    /* Set up signal handler. */
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = timer_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sigNo, &sa, NULL) == -1) {
        ASSERT_M(0);
        return (ERROR_);
    }

    /* Set and enable alarm */
    te.sigev_notify = SIGEV_SIGNAL;
    te.sigev_signo = sigNo;
    te.sigev_value.sival_ptr = p_timer_id;
    timer_create(CLOCK_REALTIME, &te, p_timer_id);

    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = usec*1000;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = usec*1000;
    timer_settime(*p_timer_id, 0, &its, NULL);
#endif
    g_resol_usec = usec;

    return (SUCCESS_);
}

void timer_stop(timer_t timer_id)
{
    timer_delete(timer_id);
}

uint32_t timer_get_resol_usec(void)
{
    return (g_resol_usec);
}

void timer_trace (void)
{
    timer_linked_list *L;
    struct TIMER_SW *p_cur_tm;
    uint32_t cnt = 0;

    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    pthread_mutex_lock (&timer_mutex);
    L = gp_linked_list;

    p_cur_tm = L->head;

    while (p_cur_tm)
    {
        DBG_PRINT(DBG_TIMER, DBG_INFO, (void *)"[%d] [%s] [%d]\n", cnt++, p_cur_tm->name, p_cur_tm->tick);
        p_cur_tm = p_cur_tm->next;
    }
    pthread_mutex_unlock (&timer_mutex);
}

int32_t timer_sw_exe (void)
{
    timer_linked_list *L;
    struct TIMER_SW *p_prv_tm, *p_cur_tm, *p_del_tm;
    

//    pthread_mutex_lock (&timer_mutex);
    L = gp_linked_list;
//    pthread_mutex_unlock (&timer_mutex);

    p_prv_tm = NULL;
    p_cur_tm = L->head;

    while (p_cur_tm)
    {
#if 1
        if (p_cur_tm->tick)
        {
            p_cur_tm->tick--;
        }

#else
        if(p_cur_tm->utc_usec && p_cur_tm->one_shot)
        {
            if(util_curtime_us() >= p_cur_tm->utc_usec)
            {
                p_cur_tm->tick = 0;
            }
        }
        else
        {
            if (p_cur_tm->tick)
            {
                p_cur_tm->tick--;
            }
        }
#endif
        if (!p_cur_tm->tick)
        {
            // Delete or Restart timer
            if (p_cur_tm->one_shot)
            {
                // Delete from Linked List
                pthread_mutex_lock (&timer_mutex);
                p_del_tm = p_cur_tm;
                if (p_prv_tm) // Middle or End node
                {
                    p_prv_tm->next = p_del_tm->next;
        
                    if (L->tail == p_del_tm) // End node
                    {
                        L->tail = p_prv_tm;
                    }
                }
                else // Front node
                {
                    L->head = p_del_tm->next;
        
                    if (L->tail == p_del_tm)
                    {
                        L->tail = NULL;
                    }
                }
        
                p_cur_tm = p_del_tm->next;
        
                // Execute timer
                p_del_tm->timer_cb(p_del_tm->in_val_1);
                
                pthread_mutex_unlock (&timer_mutex);
                
                FREE_M(p_del_tm);
            }
            else
            {
                p_cur_tm->tick = p_cur_tm->usec/g_resol_usec;
        
                // Execute timer
                p_cur_tm->timer_cb(p_cur_tm->in_val_1);
                
            }
        
            return (TIMER_LIST_CHANGED);
        }

        if (p_cur_tm)
        {
            p_prv_tm = p_cur_tm;
            p_cur_tm = p_cur_tm->next;
        }
    }

    return (SUCCESS_);
}

int32_t timer_sw_reg(uint8_t *p_name, bool one_shot, uint32_t usec, uint64_t utc_usec, _timer_cb timer_cb, int32_t in_val_1)
{
    TIMER_SW_T *p_new_tm;
    timer_linked_list *L;
    uint64_t curr_utc_usec = 0;

    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s) name(%s)\n", __FUNCTION__, p_name);

    if (!g_resol_usec)
    {
        //ASSERT_M(0);
        DBG_PRINT(DBG_TIMER, DBG_ERROR, (void *)"Error - init resolution usec\n");
        return (ERROR_);
    }
#if 0
    if (g_resol_usec > usec)
    {
        //ASSERT_M(0);
        DBG_PRINT(DBG_TIMER, DBG_ERROR, (void *)"Error - input usec\n");
        return (ERROR_);
    }
#endif
    p_new_tm = (TIMER_SW_T *)MALLOC_M(sizeof(TIMER_SW_T));
    ASSERT_M(p_new_tm);

    MEMCPY_M(p_new_tm->name, p_name, STRLEN_M((char *)p_name));
    p_new_tm->one_shot = one_shot;
    p_new_tm->utc_usec = utc_usec;

#if 1
    if (g_resol_usec <= usec)    
    {
        p_new_tm->usec = usec;
    }
    else
    {
        p_new_tm->usec = g_resol_usec;
    }

    curr_utc_usec = util_curtime_us();
    if (curr_utc_usec < utc_usec)
    {
        uint64_t cal_utc_usec = utc_usec - curr_utc_usec;
        if (g_resol_usec < cal_utc_usec)
        {
            p_new_tm->tick = cal_utc_usec/g_resol_usec;
        }
        else
        {
            p_new_tm->tick = 1;
        }
    }
    else
    {
        p_new_tm->tick = p_new_tm->usec/g_resol_usec;
    }
#else
    if (p_new_tm->one_shot && p_new_tm->utc_usec)
    {
         p_new_tm->tick = 1;
         p_new_tm->usec = 0;
    }
    else
    {
        p_new_tm->tick = usec/g_resol_usec;
        p_new_tm->usec = usec;
        p_new_tm->utc_usec = 0;
    }
#endif
    p_new_tm->timer_cb = timer_cb;
    p_new_tm->in_val_1 = in_val_1;
    
    p_new_tm->next = NULL;

    pthread_mutex_lock (&timer_mutex);
    L = gp_linked_list;
    ASSERT_M(gp_linked_list);
    
    if(L->head == NULL && L->tail == NULL)
    {
        L->head = L->tail = p_new_tm;
    }
    else 
    {
        L->tail->next = p_new_tm;
        L->tail = p_new_tm;
    }
    pthread_mutex_unlock (&timer_mutex);

    return (SUCCESS_);
}

int32_t timer_sw_dereg_by_name(uint8_t *p_name)
{
    timer_linked_list *L;

    if (!g_resol_usec)
    {
        return (ERROR_);
    }

//    pthread_mutex_lock (&timer_mutex);
    L = gp_linked_list;
//    pthread_mutex_unlock (&timer_mutex);
    
    if(L->head == NULL && L->tail == NULL)
    {
        return (ERROR_);
    }
    else 
    {
        struct TIMER_SW *p_prv_tm, *p_cur_tm;

        p_prv_tm = NULL;
        p_cur_tm = L->head;
        
        while (p_cur_tm)
        {
            if (!STRCMP_M((char *)p_cur_tm->name, (char *)p_name))
            {
                pthread_mutex_lock (&timer_mutex);
                if (p_prv_tm) // Middle or End node
                {
                    p_prv_tm->next = p_cur_tm->next;

                    if (L->tail == p_cur_tm) // End node
                    {
                        L->tail = p_prv_tm;
                    }
                }
                else // Front node
                {
                    L->head = p_cur_tm->next;

                    if (L->tail == p_cur_tm)
                    {
                        L->tail = NULL;
                    }
                }
                pthread_mutex_unlock (&timer_mutex);

                FREE_M(p_cur_tm);

                //break;
                return (SUCCESS_);
            }
            
            p_prv_tm = p_cur_tm;
            p_cur_tm = p_cur_tm->next;
        }   
    }

    return (ERROR_);
}

int32_t timer_sw_dereg(TIMER_SW_T *p_del_tm)
{
    timer_linked_list *L;

    if (!g_resol_usec)
    {
        return (ERROR_);
    }

//    pthread_mutex_lock (&timer_mutex);
    L = gp_linked_list;
//    pthread_mutex_unlock (&timer_mutex);
    
    if(L->head == NULL && L->tail == NULL)
    {
        return (ERROR_);
    }
    else 
    {
        struct TIMER_SW *p_prv_tm, *p_cur_tm;

        p_prv_tm = NULL;
        p_cur_tm = L->head;
        
        while (p_cur_tm)
        {
            if (p_cur_tm == p_del_tm)
            {
                pthread_mutex_lock (&timer_mutex);
                if (p_prv_tm) // Middle or End node
                {
                    p_prv_tm->next = p_del_tm->next;

                    if (L->tail == p_del_tm) // End node
                    {
                        L->tail = p_prv_tm;
                    }
                }
                else // Front node
                {
                    L->head = p_del_tm->next;

                    if (L->tail == p_del_tm)
                    {
                        L->tail = NULL;
                    }
                }
                pthread_mutex_unlock (&timer_mutex);

                FREE_M(p_del_tm);

                //break;
                return (TIMER_LIST_CHANGED);
            }
            
            p_prv_tm = p_cur_tm;
            p_cur_tm = p_cur_tm->next;
        }   
    }

    return (ERROR_);
}

int32_t timer_change_tick_by_name(uint8_t *p_name)
{
    timer_linked_list *L;

    if (!g_resol_usec)
    {
        return (ERROR_);
    }

//    pthread_mutex_lock (&timer_mutex);
    L = gp_linked_list;
//    pthread_mutex_unlock (&timer_mutex);
    
    if(L->head == NULL && L->tail == NULL)
    {
        return (ERROR_);
    }
    else 
    {
        struct TIMER_SW *p_cur_tm;

        p_cur_tm = L->head;
        
        while (p_cur_tm)
        {
            if (!STRCMP_M((char *)p_cur_tm->name, (char *)p_name))
            {
                p_cur_tm->tick = 0;

                //break;
                return (SUCCESS_);
            }
            
            p_cur_tm = p_cur_tm->next;
        }   
    }

    return (ERROR_);
}

#if (TIMER_TEST == ENABLED)
int32_t timer_1_test(int32_t in_val_1)
{
    int32_t ret;
    
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    ret = task_send_msg(&tx_task_pool, &tx_task_list, NULL, 0, false, TX_TASK_MSG_EVENT_01);
    if (ret == ERROR_)
    {
        ASSERT_M(0);
    }

    return (SUCCESS_);
}

int32_t timer_2_test(int32_t in_val_1)
{
    //int32_t ret;
    
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    //ret = task_send_msg(&tx_task_pool, &tx_task_list, NULL, 0, false, TX_TASK_MSG_EVENT_02);
    //if (ret == ERROR_)
    //{
    //    ASSERT_M(0);
    //}
    
    return (SUCCESS_);
}

int32_t timer_3_test(int32_t in_val_1)
{
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    return (SUCCESS_);
}

int32_t timer_4_test(int32_t in_val_1)
{
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);

    return (SUCCESS_);
}

void timer_run_test (void)
{
    DBG_PRINT(DBG_TIMER, DBG_TRACE, (void *)"(%s)\n", __FUNCTION__);
    
    //timer_sw_reg((uint8_t *)"test_01", true, 5000000, 0, timer_1_test, 0);
    timer_sw_reg((uint8_t *)"test_02", false, 10000, 0, timer_2_test, 0);
    timer_sw_reg((uint8_t *)"test_03", false, 1000000, 0, timer_3_test, 0);
    //timer_sw_reg((uint8_t *)"test_04", false, 4000000, 0, timer_4_test, 0);
}
#endif // TIMER_TEST

