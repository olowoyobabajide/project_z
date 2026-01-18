#ifndef ISOFUNC_H
#define ISOFUNC_H

#include "report.h"
#include "report.h"
void init_elf_stats();
void isoFunc(char *so_buf, size_t so_size, const char *filename, Report *r);
void report_elf_stats(Report *r);

#endif // ISOFUNC_H
