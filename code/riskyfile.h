/*
 * Copyright (c) 2026 olowoyobabajide <olowoyobabajide@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef RISKYFILE_H
#define RISKYFILE_H

void suid(char* file, Report *r);
void suidMemory(unsigned char *data, size_t size, uint32_t mode, char *filename, Report *r);
void hidden_file(char *file, Report *r);
void hidden_fileMemory(char *filename, Report *r);

#endif // RISKYFILE_H
