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
extern char buffer[PATH_MAX];

#include "analyse.h"
#include "analyseDex.h"
#include "src/checks.h"
#include "dex.h"
#include "flaghash.h"
#include "isofunc.h"
#include "riskyfile.h"


#define RESET   "\033[0m"
#define BOLD_RED    "\033[1;31m" // CRITICAL / HIGH
#define YELLOW  "\033[0;33m" // MEDIUM / WARNING
#define BLUE    "\033[0;34m" // LOW
#define GREEN   "\033[0;32m" // INFO / OK

#endif