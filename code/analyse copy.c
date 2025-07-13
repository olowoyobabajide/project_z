#include "main.h"
//extern char buffer[PATH_MAX];
/**
Over here we analyse the android manifest file for risky permissions and flags
*/

const char *permission[] = {"android.permission.SEND_SMS", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS ", "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_COARSE_LOCATION", "android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW ", "android.permission.REQUEST_INSTALL_PACKAGES",
"android.permission.INSTALL_PACKAGES", "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"};


int analyse_per(char *a)
{
    char temp[PATH_MAX];
    
 
    //snprintf(temp, PATH_MAX, "grep 'jide' %s/temp/AndroidManifest.xml", a);
    FILE *jide;
    if((jide = fopen("AndroidManifest.xml", "rb")) == NULL)
    {
        printf("Could not open file\n");
    }
    
    printf("[Manifest Scan...]\n");

    char *s;
    FILE *test = fopen("low_perm.txt", "rw");
    while(fgets(temp, PATH_MAX-1, jide))
    {
        s = strstr(temp, "<uses-permission");
        
        if (s)
        { 
            char *store
            fgets(store, 255, s);
        }
    }
    fclose(jide);
    fclose(test);
    printf("These are low level permission threats\n");
    
    

}
