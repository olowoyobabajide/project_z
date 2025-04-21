#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>

int extension(char *a);
char scan_dir(char *u);

void main(int argc, char **argv)
{
    char buffer[256];
    if (argc != 1)
    {
        printf("Too much input\n");
    }
    scanf(argv[1], "%255s", &buffer);
    nftw("/home", )

    return scan_dir(argv[1]);
}

static int nfile(const char *path, const struct stat *sb, int typeflag, struct FTW *ftbuf)
{
    path = "/home";
    if (typeflag & FTW_D)
    {
        printf("This is a directory");
        if ((sb.st_mode & 0777) == 755)
        {
            printf("Android diretory");
        }

    }

}
char scan_dir(char *u)
{

    struct dirent *de;
    struct stat buf;

    DIR *jide = opendir(u);

    if (jide == NULL)
    {
        printf("Nothing here!\n");
    }
    stat(u, &buf);
    mode_t perms = buf.st_mode & 0777;
    printf("Permission: %03o\n", perms);

    while ((de = readdir(jide)) != NULL )
    {
        
        if(de->d_type == DT_REG) 
        {    
            extension(de->d_name);
        }
    }
    closedir(jide);
}
/**
This function checks if a particular file is an apk ???
*/
int extension(char *a)
{
    const char *dot = strchr(a, '.');
    if (!dot || dot == a)
    {
        return 0;
    }

    const char *ext = dot + 1;
    if(strlen(ext) == 3 && tolower(ext[0]) == 'a' && tolower(ext[1]) == 'p' && tolower(ext[2]) == 'k')
    {
        printf("%s", a);
    }  
    else
    {
        return(0);
    }
} 