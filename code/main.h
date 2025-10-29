#ifndef MAIN_H
#define MAIN_H

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <ftw.h>
#include <fnmatch.h>
#include <libgen.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <stddef.h> // For size_t
#include <regex.h>
#include <elf.h>

#define PATH_MAX 256

#include "analyse.h"
#include "analyseDex.h"
#include "src/checks.h"
#include "dex.h"
#include "flaghash.h"
#include "isofunc.h"
#include "riskyfile.h"


#endif