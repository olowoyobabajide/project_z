#include <stdio.h>
#include <string.h>

int check(char *s);
int main(){
    
     char *a;
     //char *b = "android.permission.AUDIO\"";
     printf("Enter something ");
     scanf("%s", a);

     check(a);
     //check(b);
}

int check(char *s)
{
    // this function checks a if this particular permission is in a file
    char pre[] = "permission";

    char *a = strtok(s, pre);
    //char *result = strtok(a, ".");

    printf("%s\n", a);
}