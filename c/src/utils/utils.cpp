/**
    @file utils.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <time.h>

UTIL_CNTX_T g_util_cntx;

UTIL_CNTX_T *util_get_cntx(void)
{
    return (&g_util_cntx);
}

static void util_cntx_init(bool b_init)
{
    if (b_init)
    {
        MEMSET_M(&g_util_cntx, 0x00, sizeof(UTIL_CNTX_T));

#if (UTIL_CRC_ALGO_2 == ENABLED)
        util_make_crc_table(g_util_cntx.crc_table);
#endif // UTIL_CRC_ALGO_2
    }

    //util_time_update();
}

void util_init(bool b_init)
{
    util_cntx_init(b_init);
}

void util_system(char *p_fwd)
{
    int32_t ret;
    
    ret = system(p_fwd);
    if( ret == 127)
    {
        DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"can't execute /bin/sh!\n");
    }
    else if(ret == -1)
    {
        DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"fork error!\n");
    }
    else
    {
        DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"return value : %d\n", WEXITSTATUS(ret));
    }
}

size_t util_fread(void *ptr, size_t size, size_t count, FILE *stream)
{
    int32_t ret;
    
    ret = fread(ptr, size, count, stream);
    //ASSERT_M(ret);

    return (ret);
}

char *util_fgets(char *s, int n, FILE *stream)  
{
    return (fgets(s, n, stream));
}

#if (defined (_WIN32) || defined (_WIN64))
void usleep(DWORD waitTime)
{
	LARGE_INTEGER perfCnt, start, now;

	QueryPerformanceFrequency(&perfCnt);
	QueryPerformanceCounter(&start);

	do {
        QueryPerformanceCounter((LARGE_INTEGER*) &now);
    } while ((now.QuadPart - start.QuadPart) / float(perfCnt.QuadPart) * 1000 * 1000 < waitTime);
}
#endif // _WIN32 || _WIN64

static char *util_sh_path(void)
{
    char *p_sh_path = (char *)SH_PATH;

    DBG_PRINT (DBG_APP, DBG_INFO, (void *)"SH_PATH : %s\n", p_sh_path);

    return (p_sh_path);
}


void util_rand_init(void) 
{
    char buf[32];
    FILE *fin;

    fin = fopen("/dev/random","rb");

    if (fin)
    {
        util_fread(buf, sizeof(buf), 1, fin);
        fclose(fin);
        RAND_seed(buf, 32);
    }
}

// firewall-cmd
void util_init_fwd(void)
{
    char fwd[FWD_STR_SIZE];
    
    sprintf(fwd, "sh %s/fwd.sh init", util_sh_path());

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%s\n", fwd);
    util_system(fwd);
    
    util_reload_fwd();
}

void util_reload_fwd(void)
{
    char fwd[FWD_STR_SIZE];
    
    sprintf(fwd, "sh %s/fwd.sh reload", util_sh_path());

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%s\n", fwd);
    util_system(fwd);
}

void util_update_fwd_source(in_addr_t ip_addr)
{
    char fwd[FWD_STR_SIZE] = {0};
    
    char *p_ip_str;
    struct sockaddr_in sock_addr;

    // IP Address
    sock_addr.sin_addr.s_addr = ip_addr;
    p_ip_str = inet_ntoa(sock_addr.sin_addr);

    sprintf(fwd, "sh %s/fwd.sh source %s", util_sh_path(), p_ip_str);
    
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%s\n", fwd);
    
    util_system(fwd);
}

void util_update_fwd_source_port(uint16_t port, bool tcp)
{
    char fwd[FWD_STR_SIZE] = {0};
    char fwd_port_protocol[PORT_PRTCL_STR_SIZE] = {0};

    // Port Protocol
    sprintf(fwd_port_protocol, "%s", (tcp==true)?"tcp":"udp");
    // Port
    sprintf(fwd, "sh %s/fwd.sh source-port %d/%s", util_sh_path(), port, fwd_port_protocol);

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%s\n", fwd);
    
    util_system(fwd);
}

void util_update_fwd_rich_rule(in_addr_t src_ip_addr, uint16_t src_port, in_addr_t dst_ip_addr, uint16_t dst_port, bool tcp)
{
    char fwd[FWD_STR_SIZE] = {0};
    char fwd_port_protocol[PORT_PRTCL_STR_SIZE] = {0};
    
    char *p_ip_str, src_ip_str[IP_STR_SIZE], dst_ip_str[IP_STR_SIZE];
    struct sockaddr_in src_sock_addr, dst_sock_addr;

    // Port Protocol
    sprintf(fwd_port_protocol, "%s", (tcp==true)?"tcp":"udp");
    
    // Source IP Address
    src_sock_addr.sin_addr.s_addr = src_ip_addr;
    p_ip_str = inet_ntoa(src_sock_addr.sin_addr);
    STRCPY_M(src_ip_str, p_ip_str);

    // Destination IP Address
    dst_sock_addr.sin_addr.s_addr = dst_ip_addr;
    p_ip_str = inet_ntoa(dst_sock_addr.sin_addr);
    STRCPY_M(dst_ip_str, p_ip_str);
    
    sprintf(fwd, "sh %s/fwd.sh rich-rule %s %s %d %s", util_sh_path(), src_ip_str, dst_ip_str, dst_port, fwd_port_protocol);

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%s\n", fwd);

    util_system(fwd);
}

// Update OS Time & System Time
void util_time_update(void)
{
    util_system((char *)"sudo rdate -s time.bora.net");
    util_system((char *)"sudo hwclock --systohc");
}

//current time
uint64_t util_curtime_ms (void)
{
    // Refer : https://stackoverflow.com/questions/1952290/how-can-i-get-utctime-in-millisecond-since-january-1-1970-in-c-language
    // Check : https://currentmillis.com/
    struct timeval tv;
    uintll_t msec; // msec_since_epoch

    gettimeofday(&tv, NULL);

    msec =
        (unsigned long long)(tv.tv_sec) * 1000 +
        (unsigned long long)(tv.tv_usec) / 1000;

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%llu\n", msec);

    return (msec);
}

uint64_t util_curtime_us (void)
{
    // Refer : https://stackoverflow.com/questions/1952290/how-can-i-get-utctime-in-millisecond-since-january-1-1970-in-c-language
    // Check : https://currentmillis.com/
    struct timeval tv;
    uintll_t usec; // usec_since_epoch

    gettimeofday(&tv, NULL);

    usec =
        (unsigned long long)(tv.tv_sec) * 1000000 +
        (unsigned long long)(tv.tv_usec);

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"%llu\n", usec);

    return (usec);
}

void util_current_time_with_ms (uint64_t *p_utc_ms)
{
	*p_utc_ms  = util_curtime_ms();
}

void util_current_time_with_us (uint64_t *p_utc_us)
{
	*p_utc_us  = util_curtime_us();
}

int32_t util_hex2str(unsigned char *in, int inlen, char *out, int *outlen)
{
    int i = 0;
    char *pos = out;

    if(outlen == NULL || *outlen < (2*inlen + 1))
    {
        return (ERROR_);
    }

    for(i = 0; i < inlen; i += 1)
    {
        pos += sprintf(pos, "%02hhX", in[i]);
    }

    *outlen = pos - out + 1;

    return (SUCCESS_);
}

int32_t util_hex2str_temp(unsigned char *in, int inlen, char *out, int outlen, bool reversed)
{
    int i = 0;
    char *pos = out;

    if(outlen < (2*inlen + 1))
    {
        return (ERROR_);
    }

    if (reversed)
    {
        for(i = (inlen-1); i >= 0; i--)
        {
            pos += sprintf(pos, "%02hhX", in[i]);
        }
    }
    else
    {
        for(i = 0; i < inlen; i++)
        {
            pos += sprintf(pos, "%02hhX", in[i]);
        }
    }

    if(outlen == pos - out + 1)
       return (SUCCESS_);
    else
       return (ERROR_);
}

int32_t util_str2hex(const char *in, unsigned char *out, int *outlen)
{
    int i = 0;
    int j = 0;
    int k = 0;
    int inlen = STRLEN_M(in);
    unsigned char hex[2] = {0};

    if (inlen > 2 && in[0] == '0' && in[1] == 'x')
    {
        k += 2;
    }

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"hexR(%d) inlen(%d)\n", STRLEN_M(in), inlen);

    if(outlen == NULL || *outlen < (inlen-k)/2)
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"outlen(%d) (inlen-k)/2(%d)\n", outlen, (inlen-k)/2);
        return (ERROR_);
    }

    for(*outlen = 0, i = (0 + k); i < inlen; *outlen += 1, i += 2)
    {
        for(j = 0; j < 2; j += 1)
        {
            if(in[i+j] >= '0' && in[i+j] <= '9')        hex[j] = in[i+j] - '0';
            else if(in[i+j] >= 'a' && in[i+j] <= 'f')   hex[j] = in[i+j] - 'a' + 10;
            else if(in[i+j] >= 'A' && in[i+j] <= 'F')   hex[j] = in[i+j] - 'A' + 10;
            else return -1;
        }
        out[*outlen] = hex[0] << 4 | hex[1];
    }

    return (SUCCESS_);
}

int32_t util_str2hex_temp(const char *in, unsigned char *out, int outlen, bool reversed)
{
    int i = 0;
    int j = 0;
    int k = 0;
    int inlen = STRLEN_M(in);
    unsigned char hex[2] = {0};

    if (inlen >= 2 && in[0] == '0' && in[1] == 'x')
    {
        k += 2;
    }

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"hexR(%d) inlen(%d)\n", STRLEN_M(in), inlen);

    if((outlen < (inlen-k)/2))
    {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"outlen(%d) (inlen-k)/2(%d)\n", outlen, (inlen-k)/2);
        return (ERROR_);
    }

    for(outlen = 0, i = (0 + k); i < inlen; outlen += 1, i += 2)
    {
        for(j = 0; j < 2; j += 1)
        {
            if(in[i+j] >= '0' && in[i+j] <= '9')        hex[j] = in[i+j] - '0';
            else if(in[i+j] >= 'a' && in[i+j] <= 'f')   hex[j] = in[i+j] - 'a' + 10;
            else if(in[i+j] >= 'A' && in[i+j] <= 'F')   hex[j] = in[i+j] - 'A' + 10;
            else return -1;
        }
        out[outlen] = hex[0] << 4 | hex[1];

        DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"out[%d] = 0x%02X\n", outlen, out[outlen]);
    }

    if (reversed)
    {
        MEMCPY_REV2(out, outlen);
    }
    
    return (SUCCESS_);
}

#if (UTIL_CRC_ALGO_1 == ENABLED)
// https://stackoverflow.com/questions/21001659/crc32-algorithm-implementation-in-c-without-a-look-up-table-and-with-a-public-li
// https://www.lammertbies.nl/comm/info/crc-calculation.html
// http://www.zorc.breitbandkatze.de/crc.html
uint32_t util_crc32a(unsigned char *p_msg, uint32_t msg_len)
{
    int i, j;
    unsigned int byte, crc, mask;
    
    i = 0;
    crc = 0xFFFFFFFF;
    
    for (i = 0; i < msg_len; i++)
    {
        byte = p_msg[i];            // Get next byte.
        crc = crc ^ byte;
        
        for (j = 7; j >= 0; j--) {    // Do eight times.
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
        
        //i = i + 1;
    }

    return ~crc;
}
#endif // UTIL_CRC_ALGO_1 

#if (UTIL_CRC_ALGO_2 == ENABLED)
// https://stackoverflow.com/questions/26049150/calculate-a-32-bit-crc-lookup-table-in-c-c
// https://www.lammertbies.nl/comm/info/crc-calculation.html
// http://www.zorc.breitbandkatze.de/crc.html
void util_make_crc_table(uint32_t crc_table[])
{
    uint32_t POLYNOMIAL = 0xEDB88320;
    uint32_t remainder;
    unsigned char b = 0;
    do {
        // Start with the data byte
        remainder = b;
        for (uint32_t bit = 8; bit > 0; --bit) {
            if (remainder & 1)
                remainder = (remainder >> 1) ^ POLYNOMIAL;
            else
                remainder = (remainder >> 1);
        }
        crc_table[(size_t)b] = remainder;
    } while(0 != ++b);
}

uint32_t util_crc32b(unsigned char *p, uint32_t n, uint32_t crc_table[])
{
    uint32_t crc = 0xfffffffful;
    uint32_t i;
    
    for(i = 0; i < n; i++)
        crc = crc_table[*p++ ^ (crc&0xff)] ^ (crc>>8);
    return(~crc);
}
#endif // UTIL_CRC_ALGO_2

// Calculated CRC32
uint32_t util_cal_crc32(unsigned char *p, uint32_t n)
{
    uint32_t crc_v = 0;

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"cal crc32", p, n);
    
#if (UTIL_CRC_ALGO_1 == ENABLED)
    crc_v = util_crc32a(p, n);
#endif // UTIL_CRC_ALGO_1

#if (UTIL_CRC_ALGO_2 == ENABLED)
    crc_v = util_crc32b(p, n, g_util_cntx.crc_table);
#endif // UTIL_CRC_ALGO_2

    MEMCPY_REV(&p[n], &crc_v, UTIL_CRC_LEN);

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"crc_v = 0x%08X\n", crc_v);

    return (crc_v);
}

// Check CRC32
int32_t util_chk_crc32(unsigned char *p, uint32_t n)
{
    uint32_t crc = 0, crc_v = 0;

    MEMCPY_REV(&crc, &p[n], UTIL_CRC_LEN);

    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *)"chk crc32", p, n);
    
#if (UTIL_CRC_ALGO_1 == ENABLED)
    crc_v = util_crc32a(p, n);
#endif // UTIL_CRC_ALGO_1

#if (UTIL_CRC_ALGO_2 == ENABLED)
    crc_v = util_crc32b(p, n, g_util_cntx.crc_table);
#endif // UTIL_CRC_ALGO_2

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"crc_v = 0x%08X / crc = 0x%08X\n", crc_v, crc);

    return ((crc == crc_v) ? SUCCESS_ : ERROR_);
}


void util_get_my_ip_addr(void)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);
        }
    }

    freeifaddrs(ifap);
    
    return;
}

int32_t util_is_my_ip_addr(in_addr_t ip_addr)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;
    uint32_t ret = ERROR_;

    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            if (sa->sin_addr.s_addr == ip_addr)
            {
                addr = inet_ntoa(sa->sin_addr);
                DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"It's my IP : Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);

                ret = SUCCESS_;

                break;
            }
        }
    }

    freeifaddrs(ifap);
    
    return (ret);
}

static void util_native_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
    /* ecx is often an input as well as an output. */
    asm volatile("cpuid"
        : "=a" (*eax),
          "=b" (*ebx),
          "=c" (*ecx),
          "=d" (*edx)
        : "0" (*eax), "2" (*ecx));
}

void util_cpu_serial_info(void)
{
    // https://stackoverflow.com/questions/6491566/getting-the-machine-serial-number-and-cpu-id-using-c-c-in-linux
    unsigned int eax, ebx, ecx, edx;
#if 0
    eax = 1; /* processor info and feature bits */
    util_native_cpuid(&eax, &ebx, &ecx, &edx);
    
    printf("stepping %d\n", eax & 0xF);
    printf("model %d\n", (eax >> 4) & 0xF);
    printf("family %d\n", (eax >> 8) & 0xF);
    printf("processor type %d\n", (eax >> 12) & 0x3);
    printf("extended model %d\n", (eax >> 16) & 0xF);
    printf("extended family %d\n", (eax >> 20) & 0xFF);
#endif
    /* EDIT */
    eax = 3; /* processor serial number */
    ebx = 0;
    ecx = 0;
    edx = 0;
    util_native_cpuid(&eax, &ebx, &ecx, &edx);
    
    /** see the CPUID Wikipedia article on which models return the serial 
        number in which registers. The example here is for 
        Pentium III */
    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"serial number 0x%08X%08X\n", edx, ecx);
}

void util_hdd_serial_info(void)
{
    // https://stackoverflow.com/questions/6491566/getting-the-machine-serial-number-and-cpu-id-using-c-c-in-linux
    static struct hd_driveid hd;
    int fd;
    
    if ((fd = open("/dev/sda1", O_RDONLY | O_NONBLOCK)) < 0) {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR opening /dev/sda\n");

        return;
    }
    
    if (!ioctl(fd, HDIO_GET_IDENTITY, &hd)) {
        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"%.20s\n", hd.serial_no);
    } else if (errno == -ENOMSG) {
        DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"No serial number available\n");
    } else {
        DBG_PRINT(DBG_UTIL, DBG_ERROR, (void *)"ERROR: HDIO_GET_IDENTITY\n");
    }
}

void util_bios_serial_info(void)
{
    // https://zetawiki.com/wiki/%EC%84%9C%EB%B2%84_%EC%8B%9C%EB%A6%AC%EC%96%BC_%EB%B2%88%ED%98%B8_%ED%99%95%EC%9D%B8
    uint8_t *p_bios_sn;
    uint32_t len;

    util_system((char *)"sudo dmidecode -s system-serial-number | tail -1 > sn.txt");

    FILE *fp = fopen("sn.txt","r");

    if(fp)
    {
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);

        p_bios_sn = (uint8_t *)MALLOC_M(len);

        if (p_bios_sn)
        {
            fseek(fp, 0, SEEK_SET);
            util_fread(p_bios_sn, len, 1, fp);
            p_bios_sn[len-1] = 0;
            
            util_remove_file("sn.txt");  

            DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"system serial len(%d) (%s)\n", len, p_bios_sn);

            FREE_M(p_bios_sn);
        }

        fclose(fp);          //cleanup temp file
    }
}

uint32_t util_bios_uuid_info(uint8_t **p_bios_sn)
{
    // https://brownbears.tistory.com/225
    uint32_t len = 0;

    util_system((char *)"sudo dmidecode -s system-uuid > uuid.txt");
    
    FILE *fp = fopen("uuid.txt","r");

    if (fp)
    {
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);

        if (!*p_bios_sn)
        {
            *p_bios_sn = (uint8_t *)MALLOC_M(len);
        }

        if (*p_bios_sn)
        {
            fseek(fp, 0, SEEK_SET);
            util_fread(*p_bios_sn, len, 1, fp);
            (*p_bios_sn)[len-1] = 0;
            
            util_remove_file("uuid.txt");  

            //DBG_PRINT(DBG_UTIL, DBG_INFO, (void *)"system uuid len(%d) (%s)\n", len, *p_bios_sn);
        }
        
        fclose(fp);          //cleanup temp file
    }
    
    return (len);
}

int32_t util_create_dir(const char *fdir)
{
    int32_t ret = SUCCESS_;
    
    struct stat st = {0};
    
    if (stat(fdir, &st) == -1) {
        mkdir(fdir, 0755); // 0700
    }

    return (ret);
}

int32_t util_exists_dir(const char *fdir)
{
    DIR* dir = opendir(fdir);

    if (dir)
    {
        /* Directory exists. */
        closedir(dir);
        
        return (SUCCESS_);
    }
    else if (ENOENT == errno)
    {
        /* Directory does not exist. */
    }
    else
    {
        /* opendir() failed for some other reason. */
    }

    return (ERROR_);
}

int32_t util_remove_dir(const char *fdir)
{
    int32_t res;

    res = rmdir( fdir ); // rm -r xxxx

    if( res == SUCCESS_)
    {
        //
    }
    else if ( res == ERROR_)
    {
        //
    }

    return (SUCCESS_);
}


int32_t util_exists_file(const char *fname)
{
#if 0
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
        fclose(file);
        return SUCCESS_;
    }
    return ERROR_;
#else
    if( access( fname, F_OK ) != -1 ) {
        // file exists
        return (SUCCESS_);
    }

    return (ERROR_);
#endif
}

int32_t util_remove_file(const char *fname)
{
    int32_t ret = SUCCESS_;
    
    remove(fname);

    return (ret);

}

int32_t util_exists_fd(int32_t fd)
{
    struct stat buf;
    
    if (fstat(fd, &buf) == -1) {
        // fd is either closed or not accessible 
        return (ERROR_);
    }

    return (SUCCESS_);
}

int32_t util_file_w(char *p_path, uint8_t *p_buf, uint32_t buf_len)
{
    int32_t ret = ERROR_;
    FILE *fp; 
    
    fp = fopen(p_path, "w");

    if (fp)
    {
        if (p_buf && buf_len)
        {
            fwrite(p_buf, buf_len, 1, fp);
        }

        ret = SUCCESS_;
        
        fclose(fp);
    }
    
    return (ret);
}

int32_t util_file_a(char *p_path, uint8_t *p_buf, uint32_t buf_len)
{
    int32_t ret = ERROR_;
    FILE *fp; 
    
    fp = fopen(p_path, "a");

    if (fp)
    {
        if (p_buf && buf_len)
        {
            fwrite(p_buf, buf_len, 1, fp);
        }

        ret = SUCCESS_;
        
        fclose(fp);
    }

    return (ret);
}

char *util_file_r(char *p_path, uint32_t *p_buf_len)
{
    FILE *fp;
    char *p_buf;

    *p_buf_len = 0;
    
    fp = fopen (p_path, "r");
    if (!fp)
    {
        return (NULL);
    }

    fseek(fp, 0, SEEK_END); 
    *p_buf_len = ftell(fp);

    if (*p_buf_len == 0)
    {
        fclose(fp);
        
        return (NULL);
    }
    
    p_buf = (char *)MALLOC_M(*p_buf_len);
    MEMSET_M(p_buf, 0, *p_buf_len);

    fseek(fp, 0, SEEK_SET);
    util_fread(p_buf, *p_buf_len, 1, fp); 

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"file_r_buf_len: %d\n", *p_buf_len);
    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *) "file_r_buf", (uint8_t *)p_buf, *p_buf_len);

    fclose(fp);
    
    return (p_buf);
}


int32_t util_hex_file_wb(char *p_path, uint8_t *p_buf, uint32_t buf_len)
{
    int32_t ret = ERROR_;
    FILE *fp; 
    
    fp = fopen(p_path, "wb");
    if (fp)
    {
        fwrite(p_buf, buf_len, 1, fp);

        ret = SUCCESS_;
        
        fclose(fp);
    }
    
    return (ret);
}

char *util_hex_file_rb(char *p_path, uint32_t *p_buf_len)
{
    FILE *fp;
    char *p_buf;

    *p_buf_len = 0;
    
    fp = fopen (p_path, "rb");
    if (!fp)
    {
        return (NULL);
    }

    fseek(fp, 0, SEEK_END); 
    *p_buf_len = ftell(fp);

    if (*p_buf_len == 0)
    {
        fclose(fp);
        
        return (NULL);
    }
    
    p_buf = (char *)MALLOC_M(*p_buf_len);
    MEMSET_M(p_buf, 0, *p_buf_len);

    fseek(fp, 0, SEEK_SET);
    util_fread(p_buf, *p_buf_len, 1, fp); 

    DBG_PRINT(DBG_UTIL, DBG_NONE, (void *)"file_rb_buf_len: %d\n", *p_buf_len);
    DBG_DUMP(DBG_UTIL, DBG_NONE, (void *) "file_rb_buf", (uint8_t *)p_buf, *p_buf_len);

    fclose(fp);
    
    return (p_buf);
}

char *util_slice_str(const char *p_str, uint32_t start, uint32_t end)
{
    char *p_buf;
    uint32_t cnt1, cnt2;

    if (start >= end)
    {
        return (NULL);
    }

    if (STRLEN_M(p_str) < end)
    {
        return (NULL);
    }

    p_buf = (char *)MALLOC_M(end - start + 1);

    ASSERT_M(p_buf);

    cnt2 = 0;
    
    for (cnt1 = start; cnt1 < end; cnt1++ )
    {
        p_buf[cnt2++] = p_str[cnt1];
    }
    
    p_buf[cnt2] = 0;

    return (p_buf);
}

int32_t util_str_upper_case(char *p_str, uint32_t len)
{
    uint32_t cnt;

    if (STRLEN_M(p_str) < len)
    {
        return (ERROR_);
    }
    
    for (cnt = 0; cnt < len; cnt++)
    {
        if(p_str[cnt] >= 'a' && p_str[cnt] <= 'z')
        {
            p_str[cnt] = p_str[cnt] - 32;
        }
    }

    return (SUCCESS_);
}

int32_t util_str_lower_case(char *p_str, uint32_t len)
{
    uint32_t cnt;

    if (STRLEN_M(p_str) < len)
    {
        return (ERROR_);
    }
    
    for (cnt = 0; cnt < len; cnt++)
    {
        if(p_str[cnt] >= 'A' && p_str[cnt] <= 'Z')
        {
            p_str[cnt] = p_str[cnt] + 32;
        }
    }

    return (SUCCESS_);
}

double util_round_up(double val, uint32_t f_p)
{
    double ret_val;

    ret_val = val * f_p;
    DBG_PRINT (DBG_UTIL, DBG_NONE, (void *)"1 ret_val is %f\n", ret_val);
    ret_val = ROUNDF_UP(ret_val);
    DBG_PRINT (DBG_UTIL, DBG_NONE, (void *)"2 ret_val is %f\n", ret_val);
    ret_val = ret_val / f_p;
    DBG_PRINT (DBG_UTIL, DBG_NONE, (void *)"3 ret_val is %f\n", ret_val);

    return (ret_val);
}

double util_round_down(double val, uint32_t f_p)
{
    double ret_val;

    ret_val = val * f_p;
    DBG_PRINT (DBG_UTIL, DBG_NONE, (void *)"1 ret_val is %f\n", ret_val);
    ret_val = ROUNDF_DOWN(ret_val);
    DBG_PRINT (DBG_UTIL, DBG_NONE, (void *)"2 ret_val is %f\n", ret_val);
    ret_val = ret_val / f_p;
    DBG_PRINT (DBG_UTIL, DBG_NONE, (void *)"3 ret_val is %f\n", ret_val);

    return (ret_val);
}


