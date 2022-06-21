/**
    @file get_rss_cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

// http://nadeausoftware.com/articles/2012/07/c_c_tip_how_get_process_resident_set_size_physical_memory_use

#include "global.h"

typedef struct {
    long size,resident,share,text,lib,data,dt;
} statm_t;

void read_off_memory_status(statm_t *p_result)
{
    //unsigned long dummy;
    const char* statm_path = "/proc/self/statm";

    FILE *f = fopen(statm_path,"r");
    if(!f){
        perror(statm_path);
        abort();
    }
    if(7 != fscanf(f,"%ld %ld %ld %ld %ld %ld %ld", &p_result->size, &p_result->resident, &p_result->share, &p_result->text, &p_result->lib, &p_result->data, &p_result->dt))
    {
        perror(statm_path);
        abort();
    }
    fclose(f);
}

void get_current_rss_monitor(uint32_t dbg_level, char *p_info)
{
    statm_t result;

    if (dbg_level < DBG_NONE)
    {
        read_off_memory_status(&result);
        
        DBG_PRINT(DBG_UTIL, (DBG_LEVEL_E) dbg_level, (void *)"%s : current_size(%llu)\n", p_info, (result.resident*4));
    }
}

