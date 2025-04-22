#include "main.h"
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <ftw.h>
#include <fnmatch.h>
#include <libgen.h>
#define PATH_MAX 256

int main(int argc, char **argv)
{
    char buffer[PATH_MAX];

    sscanf(argv[1], "%255s", &buffer);
    apk_check(buffer);

    unzip_apk(basename(base_path));

}