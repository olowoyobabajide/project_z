#ifndef CHECKS_H
#define CHECKS_H

#include "../report.h"

int filecheckDex(char *file_path, int enable_dex_log, Report *r);
int filecheckso(char *file_path, Report *r);
int apk_check(char *apk);
int filecheckManifest(char *file_path, Report *r);
int filecheckAll(char *file_path, Report *r);

#endif // CHECKS_H
