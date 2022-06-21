/**
    @file global.h
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#ifndef __GLOBAL_H__
#define __GLOBAL_H__

//#ifdef __cplusplus
//extern "C"
//{
//#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h> // For boolean type
#include <stdarg.h> // printf
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <semaphore.h>
#include <pthread.h>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <execinfo.h>

#if (defined (_WIN32) || defined (_WIN64))
#include <Windows.h>
#else
#include <unistd.h>
#endif

// C++
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>    /* For SYS_xxx definitions */
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ipc.h> 
#include <sys/msg.h> 

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <linux/netlink.h>
#include <linux/hdreg.h>

// Epoll
#include <sys/epoll.h>
#include <fcntl.h>

//Compilation flags used to enable/disable features
#define ENABLED  1
#define DISABLED 0

#define SUCCESS_ 0
#define ERROR_ -1

#define UNUSED_FUNC_1 DISABLED
#define UNUSED_FUNC_2 DISABLED
#define UNUSED_FUNC_3 DISABLED
#define UNUSED_FUNC_4 DISABLED

// CUnit
#include "CUnit.h"
#include "Console.h"
#include "Basic.h"

// CURL
//#include <curl/curl.h>

#if defined(USE_JSONC)
// JSON-C
#include "json.h"
#endif // USE_JSONC

// Utils
#include "utils_global.h"

// SEC
#include "sec_global.h"

// Net
#include "net_global.h"

// P2P
#include "p2p_global.h"

// CONSENSUS
#include "cons_global.h"

// DB
#include "db_global.h"

// CLI
#include "cli_global.h"

//#ifdef __cplusplus
//}
//#endif

#endif /* __GLOBAL_H__ */
