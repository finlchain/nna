/**
    @file utils_types.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __UTIL_TYPES_H__
#define __UTIL_TYPES_H__

#define UTIL_CRC_ALGO_1 DISABLED // ENABLED DISABLED
#define UTIL_CRC_ALGO_2 ENABLED // ENABLED DISABLED
#define UTIL_CRC_LEN    4
#define UTIL_UUID_STR_LEN   36

#if (UTIL_CRC_ALGO_2 == ENABLED)
#define UTIL_CRC_TABLE_SIZE 256
#endif

#endif /* __UTIL_TYPES_H__ */

