#include <zebra.h>

#define VT100_RESET "\x1b[0m"
#define VT100_RED "\x1b[31m"
#define VT100_GREEN "\x1b[32m"
#define VT100_YELLOW "\x1b[33m"
#define OK VT100_GREEN "OK" VT100_RESET
#define FAILED VT100_RED "failed" VT100_RESET

struct thread_master *master = NULL;

int 
main (int argc, int **argv)
{
  printf (OK "\n");
}
