/**
    @file db_global.h
    @date 2019/02/12
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __DB_GLOBAL_H__
#define __DB_GLOBAL_H__

//#ifdef __cplusplus
//extern "C"
//{
//#endif

#define DB_DROP_DATABASE DISABLED // ENABLED DISABLED
#define DB_TRUNCATE_TABLES DISABLED // ENABLED DISABLED

#define DB_PATH_STR_LEN 300

////////////////////////////////////////
// DB REDIS
#if defined (USE_LIBAE)
#include "adapters/ae.h"
#endif // USE_LIBAE
#if defined (USE_LIBEV)
#include "adapters/libev.h"
#endif // USE_LIBEV
#if defined (USE_LIBEVENT)
#include "adapters/libevent.h"
#endif // USE_LIBEVENT


#if defined(USE_MYSQL) // if mysql
// DB MYSQL
#include "mysql.h"
#elif defined(USE_MONGODB) // if mongo
// DB MONGOC
#include "bson/bson.h"
#include "mongoc/mongoc.h"
#endif

//

// DB 1
#include "db_config.h"
#include "db_types.h"
#include "db_interface.h"

// DB REDIS
#if (defined (USE_LIBAE) || defined (USE_LIBEV) || defined (USE_LIBEVENT))
#include "db_redis.h"
#include "db_redis_task_msg.h"
#endif // USE_LIBNONE

#if defined(USE_MYSQL) // if mysql
// DB MYSQL
#include "db_mysql.h"
#elif defined(USE_MONGODB) // if mongo
// DB MONGOC
#include "db_mongodb.h"
#endif

// DB 2
#include "db_timer.h"
#include "db.h"
#include "db_task_msg.h"


////////////////////////////////////////

//#ifdef __cplusplus
//}
//#endif

#endif /* __DB_GLOBAL_H__ */

