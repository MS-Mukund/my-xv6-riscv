#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char **argv)
{
    // int priority;
    if(argc != 3) {
       fprintf(2, "usage: setpriority <priority>(0,100) <pid>\n");
        exit(1);
    }

    int priority = atoi(argv[1]);
    if( priority < 0 || priority > 100 ) {
        fprintf(2, "priority must be between 0 and 100\n");
        exit(2);
    }

    int pid = atoi(argv[2]);
    if( pid < 0 ) {
        fprintf(2, "invalid pid\n");
        exit(3);
    }

    int old = setpriority(priority, pid, 5);
    if( old < 0)
    {
        exit(4);
    }
    
    exit(0);
}
