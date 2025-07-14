#include "main.h"
//extern char buffer[PATH_MAX];
/**
Over here we analyse the android manifest file for risky permissions and flags
*/

/*const char *permission[] = {"android.permission.SEND_SMS", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS ", "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_COARSE_LOCATION", "android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW ", "android.permission.REQUEST_INSTALL_PACKAGES",
"android.permission.INSTALL_PACKAGES", "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"};*/


int analyse_per(char *a)
{
    char perm[PATH_MAX];
    FILE *AndroidManifest;
    FILE *permission,*activity, *service, *receiver, *provider, *application;
    
    if ((AndroidManifest = fopen("AndroidManifest.xml", "rb")) == NULL)
    {
        perror("The AndroidManifest file could not be open");
    }
    /*if ((permission = fopen("permission.txt", "a")) == NULL)
    {
        perror("Could not open this file");
    }
    /*if ((activity = fopen("activity.txt", "a")) == NULL || (service = fopen("services.txt", "a")) == NULL
|| (receiver = fopen("receiver.txt", "a")) == NULL || (provider = fopen("provider.txt", "a")) == NULL)
    {
        perror("Could not open the file");
    }*/
    char *s, *app, *act, *ser, *rec, *prov;
    while(fgets(perm, PATH_MAX-1, AndroidManifest))
    {
        
        if ((s = strstr(perm, "uses-permission")) != NULL && (permission = fopen("permission.txt", "a")) != NULL)
        {
            fprintf(permission, "%s", s);
        }
        if ((act = strstr(perm, "activity")) != NULL && (activity = fopen("activity.txt", "a")) != NULL)
        {
            fprintf(activity, "%s", perm);
        }
        if (strstr(perm, "service") != NULL && (service = fopen("services.txt", "a")) != NULL)
        {
            fprintf(service, "%s", perm);
        }
        if (strstr(perm, "receiver") != NULL && (receiver = fopen("receiver.txt", "a")) != NULL)
        {
            fprintf(service, "%s", perm);
        }
        if ((prov = strstr(perm, "provider")) != NULL && (provider = fopen("providers.txt", "a")) != NULL)
        {
            fprintf(service, "%s", prov);
        }
        if ((app = strstr(perm, "application")) != NULL && (application = fopen("app.txt", "a")) != NULL)
        {
            fprintf(service, "%s", app);
        }
    }

    fclose(AndroidManifest);
}
