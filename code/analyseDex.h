#ifndef ANALYSEDEX_H
#define ANALYSEDEX_H

#include <stdint.h>

void analyseDex(
    char **str, int str_count,
    char **typ, int typ_count,
    char **class, int class_count,
    char **method, int method_count,
    char **meth_class, int meth_class_count,
    char **super_class, int super_class_count
);

#endif // ANALYSEDEX_H
