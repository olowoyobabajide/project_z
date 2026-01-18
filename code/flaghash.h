#ifndef FLAGHASH_H
#define FLAGHASH_H

void verifyHash(char *file, Report *r);
void verifyHashMemory(unsigned char *data, size_t size, char *filename, Report *r);

#endif // FLAGHASH_H
