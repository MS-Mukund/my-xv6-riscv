#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include <stddef.h>

int isdigit(char c)
{
    if( c >= '0' && c <= '9')
        return 1;
    return 0;
}

int
main(int argc, char **argv)
{
    if(argc <= 2 )
    {
        fprintf(2, "Usage: %s mask command <args>\n", argv[0]);
        exit(1);
    }
    if( !isdigit(argv[1][0]) )
    {
        fprintf(2, "provide correct mask\n");
        exit(1);
    }

    int ret = trace( atoi(argv[1]) );
    if ( ret < 0) {
        fprintf(2, "%s: trace() error\n", argv[0]); // write to stderr
        exit(1);
    }
    
    for(int i = 2; i < argc; i++)
    {
    	strcpy(argv[i-2], argv[i]);
    }
    argc -= 2;
    argv[argc][0] = '\0';
    argv[argc+1][0] = '\0';
    argv[argc] = NULL;

    exec(argv[0], argv);
    exit(0);
} 