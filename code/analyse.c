#include "main.h"
int jide(char *a);
extern char buffer[PATH_MAX];
/**
Over here we analyse the android manifest file for risky permissions and flags
*/

/*enum permission {SEND_SMS = 1, RECEIVE_SMS, RECEIVE_SMS, CALL_PHONE, READ_CALL_LOG, WRITE_CALL_LOG, RECORD_AUDIO, CAMERA,
READ CONTACTS, WRITE_CONTACTS, ACCESS_FINE_LOCATION, INTERNET, SYSTEM_ALERT_WINDOW, INSTALL_PACKAGES,
READ_EXTERNAL_STORAGE};*/

typedef struct{
    char *low;
}pers;

int jide(char *a)
{
    char temp[PATH_MAX];
    
    //snprintf(temp, PATH_MAX, "grep 'jide' %s/temp/AndroidManifest.xml", a);
    
    FILE *jide;
    if ((jide = fopen("AndroidManifest.xml", "rb")) == NULL)
    {
        printf("Could not open file\n");
    }

    printf("[Manifest Scan...]\n");
    //pers->low = {" "};
    while(fgets(temp, PATH_MAX-1, jide) != NULL)
    {
        char *s;
        char put[PATH_MAX];
        if((s = strstr(temp, "RECORD_AUDIO")) != NULL || (s = strstr(temp, "VIBRATE")) != NULL)
        {
            printf("These are low level permission threats\n");
            pers->low = snprintf(put, PATH_MAX-1, "%s\n ", strtok(s, "\"/>"));
        }
    }
    printf("Permissions: %s", pers->low);
    fclose(jide);
}
