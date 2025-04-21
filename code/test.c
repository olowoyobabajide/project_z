#include <stdio.h>
#include <elf.h>

int main()
{
    FILE *head;

    Elf64_Ehdr jide;
    if ((head = fopen("a.out", "rb")) == NULL)
    {
        printf("Could not open file\n");
    }
    else
    {
        printf("%08x", jide.e_ident[EI_MAG1]);
    }
    fclose(head);
}