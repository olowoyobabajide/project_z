#include "main.h"
int jide(char *a);
extern char buffer[PATH_MAX];

/*enum permission {SEND_SMS = 1, RECEIVE_SMS, RECEIVE_SMS, CALL_PHONE, READ_CALL_LOG, WRITE_CALL_LOG, RECORD_AUDIO, CAMERA,
READ CONTACTS, WRITE_CONTACTS, ACCESS_FINE_LOCATION, INTERNET, SYSTEM_ALERT_WINDOW, INSTALL_PACKAGES,
READ_EXTERNAL_STORAGE};*/

int jide(char *a)
{
    char temp[PATH_MAX];
    
    snprintf(temp, PATH_MAX, "grep 'jide' %s/temp/AndroidManifest.xml", a);
    
    if (system(temp) == -1)
    {
        printf("Can't find this\n");
        return 1;
    }
    /*if (WIFSIGNALED(ret) && (WTERMSIG(ret) == SIGINT || WTERMSIG(ret) == SIGQUIT))
    {
        break;
    }*/
    printf("\nThis Apk can receive files");
}

    
