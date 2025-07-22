#include "main.h"

void tag_check(char *a);
int main(int argc, char **argv)
{
    static char buffer[PATH_MAX];

    if (argc != 2)
    {
        printf("Insufficient or too much input\n");
        printf("Try './main /path/to/folder\n'");
        return EXIT_FAILURE;
    }
    sscanf(argv[1], "%255s", &buffer);

   /* if (apk_check(buffer) == -1)
    {
        printf("NFTW\n");
        return 1;
    }*/
    //analyse_per(buffer);
    char *a = "permission.txt";
    tag_check(a);
    
}