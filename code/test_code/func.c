#include <stdio.h>
#include <string.h>

int main(void)
{
    FILE *j = fopen("AndroidMAnifest.xml", "rb");
    FILE *keep = fopen("jide.txt", "w");
    char *s = "jide is number one";
    if (j == NULL)
    {
        printf("Could not open file");
    } 
    fprintf(keep, "%s", s);
        
    
    fclose(j);
    fclose(keep);

}