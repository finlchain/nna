/**
    @file backtrace.cpp
    @date 2019/06/03
    @author FINL Chain Team
    @version 
    @brief 
*/

#include "global.h"
#include <execinfo.h>

//#define BT_ADDR2LINE
#define BT_NORMAL

#if defined (BT_ADDR2LINE)
static char const *icky_global_program_name;

/* Resolve symbol name and source location given the path to the executable 
   and an address */
int addr2line(char const * const program_name, void const * const addr)
{
  char addr2line_cmd[512] = {0};

  /* have addr2line map the address to the relent line in the code */
  #ifdef __APPLE__
    /* apple does things differently... */
    sprintf(addr2line_cmd,"sudo atos -o %.256s %p", program_name, addr); 
  #else
    sprintf(addr2line_cmd,"sudo addr2line -f -p -e %.256s %p", program_name, addr); 
  #endif

  return system(addr2line_cmd);
}

#define MAX_STACK_FRAMES 64
static void *stack_traces[MAX_STACK_FRAMES];
void posix_print_stack_trace()
{
    int i, trace_size = 0;
    char **messages = (char **)NULL;

    trace_size = backtrace(stack_traces, MAX_STACK_FRAMES);
    messages = backtrace_symbols(stack_traces, trace_size);

    /* skip the first couple stack frames (as they are this function and
    our handler) and also skip the last frame as it's (always?) junk. */
    // for (i = 3; i < (trace_size - 1); ++i)
    // we'll use this for now so you can see what's going on
    for (i = 0; i < trace_size; ++i)
    {
        if (addr2line(icky_global_program_name, stack_traces[i]) != 0)
        {
            printf("  error determining line # for: %s\n", messages[i]);
        }
    }
    
    if (messages) { free(messages); } 
}
#endif // BT_ADDR2LINE

#if defined (BT_NORMAL)
#define BT_BUF_SIZE 100

char addr[100] = {0};

char *bt_sed_addr(char *p_str)
{
    uint32_t str_len, idx, idx_s = 0, addr_len = 0;
//    char addr2line_cmd[512] = {0};

    str_len = (uint32_t)STRLEN_M(p_str);
    
//    printf("sed addr : size (%d), %s\n", str_len, p_str);

    for (idx=0; idx<str_len; idx++)
    {
        if (p_str[idx] == '[')
        {
//            printf("[ : %d\n", idx);
            idx_s = idx;
        }
        else if (p_str[idx] == ']')
        {
//            printf("] : %d\n", idx);
            addr_len = idx - idx_s - 1;
        }
    }

    MEMSET_M(addr, 0x00, sizeof(addr));
    MEMCPY_M(addr, &p_str[idx_s+1], addr_len);
    
    return (addr);
}

void bt_file_in(int nptrs, char **pp_strs)
{
    FILE *fp, *fp_2;
    int j;

    fp=fopen("out.txt", "w");
    fp_2=fopen("out_addr.txt", "w");

    //fputs("Hello, World! ", fp);
    //fprinf(fp, "Another? %s", to_a_txt);

    for (j = 0; j < nptrs; j++)
	{
		fprintf(fp, "%4d %s\n", nptrs - 1 - j, pp_strs[j]);
        fprintf(fp_2, "%4d %s\n", nptrs - 1 - j, bt_sed_addr(pp_strs[j]));
	}

	fprintf(fp, "\n");
	fprintf(fp, "U can find line number using \"addr2line -fe [Application] [BINARY ADDRESS]\"\n");
	fprintf(fp, "\n");

    fclose(fp);
    fclose(fp_2);
}

void bt_func_print(void)
{
    int nptrs;
    
	void *p_buf[BT_BUF_SIZE];
	char **pp_strs;

	nptrs = backtrace(p_buf, BT_BUF_SIZE);
    printf("backtrace() returned %d addresses\n", nptrs);

    /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
       would produce similar output to the following: */

	pp_strs = backtrace_symbols(p_buf, nptrs);
	if (pp_strs == NULL) {
		perror("backtrace_symbols");
		exit(EXIT_FAILURE);
	}

    bt_file_in(nptrs, pp_strs);

	free(pp_strs);
}
#endif // BT_NORMAL

// sig ==> signal number
void calltrace(int sig)
{
#if defined (BT_ADDR2LINE)
//    posix_print_stack_trace();
#else
    bt_func_print();
#endif

	exit(255);
}

void addSignal(char *argv)
{
	(void) signal (SIGSEGV,  calltrace); // Segment Error
	(void) signal (SIGINT,   calltrace); // Interupt with CTRL+C
	(void) signal (SIGILL,   calltrace); // Iillegal Command
	(void) signal (SIGABRT,  calltrace); // Abort
	//(void) signal (SIGPIPE,  calltrace);
	(void) signal (SIGKILL,  calltrace); // KILL Command
	(void) signal (SIGFPE,  calltrace);
    (void) signal (SIGTERM, calltrace);

#if defined (BT_ADDR2LINE)
    icky_global_program_name = argv;
#endif // BT_ADDR2LINE
}

#ifdef   _UNIT_TEST_
#include <time.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
	addSignal();

	printf("Test begin\n");

	if (time(NULL) % 2)
	{
		int   i    = 0;

		for (i=0; i < argc + 100; i++)
		{
			printf("test print: %3d : %s\n", i, argv[i]);
		}
	}
	else
	{
		abort();
	}

	return 0;
}
#endif // _UNIT_TEST_

