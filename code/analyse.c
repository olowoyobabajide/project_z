#include "main.h"
//extern char buffer[PATH_MAX];
/*
Over here we analyse the android manifest file for risky permissions and flags
*/
#define keep 10000
char* replace_str(const char *r);
const char *permission[24] = {" ","android.permission.READ_SMS","android.permission.SEND_SMS","android.permission.RECEIVE_SMS",
"android.permission.READ_CONTACTS","android.permission.WRITE_CONTACTS","android.permission.GET_ACCOUNTS",
"android.permission.RECORD_AUDIO","android.permission.CAMERA","android.permission.READ_PHONE_STATE",
"android.permission.CALL_PHONE","android.permission.READ_CALL_LOG","android.permission.WRITE_CALL_LOG",
"android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_COARSE_LOCATION","android.permission.READ_EXTERNAL_STORAGE",
"android.permission.WRITE_EXTERNAL_STORAGE","android.permission.INTERNET","android.permission.SYSTEM_ALERT_WINDOW",
"android.permission.BIND_ACCESSIBILITY_SERVICE","android.permission.REQUEST_INSTALL_PACKAGES",
"android.permission.VIBRATE","android.permission.WAKE_LOCK","android.permission.RECEIVE_BOOT_COMPLETED"};


int analyse_per(char *a)
{
    char perm[PATH_MAX];
    FILE *AndroidManifest;
    FILE *permission,*activity, *service, *receiver, *provider, *application;
    
    if ((AndroidManifest = fopen("AndroidManifest.xml", "rb")) == NULL)
    {
        perror("The AndroidManifest file could not be open");
    }
    char *s, *app, *act, *ser, *rec, *prov;
    while(fgets(perm, PATH_MAX-1, AndroidManifest))
    {
        
        if (strstr(perm, "uses-permission")!= NULL && (permission = fopen("permission.txt", "a+")) != NULL)
        {
            fprintf(permission, "%s", perm);
            fclose(permission);
        }
        if (strstr(perm, "activity") != NULL && (activity = fopen("activity.txt", "a+")) != NULL)
        {
            fprintf(activity, "%s", perm);
            fclose(activity);
        }
        if (strstr(perm, "service") != NULL && (service = fopen("services.txt", "a+")) != NULL)
        {
            fprintf(service, "%s", perm);
            fclose(service);
        }
        if (strstr(perm, "receiver") != NULL && (receiver = fopen("receiver.txt", "a+")) != NULL)
        {
            fprintf(receiver, "%s", perm);
            fclose(receiver);
        }
        if (strstr(perm, "provider") != NULL && (provider = fopen("providers.txt", "a+")) != NULL)
        {
            fprintf(provider, "%s", perm);
            fclose(provider);
        }
        if (strstr(perm, "application") != NULL && (application = fopen("app.txt", "a+")) != NULL)
        {
            fprintf(application, "%s", perm);
            fclose(application);
        }
    }
    
    fclose(AndroidManifest);
}

typedef struct reason_perms{
    char *name;
    char *level;
}rperm;
void tag_perm(char *a)
{
    
    FILE *file = fopen(a, "rb");
    FILE *log;
    char perm[PATH_MAX];

    if (file == NULL)
    {
        perror("File could not be read\n");
    }
    
    char *ptr = perm;
    char *header_perm = "Permission: ";
    rperm rperms[] = {{" "," "},
{"android.permission.READ_SMS","\nLevel: DANGEROUS\nReason: Allows reading of user's private SMS messages\n-------\n"},
{"android.permission.SEND_SMS","\nLevel: DANGEROUS\nReason: Can send SMS without user consent (used for scams)\n-------\n"},
{"android.permission.RECEIVE_SMS","\nLevel: DANGEROUS\nReason: Can intercept incoming SMS (used for OTP theft)\n-------\n"},
{"android.permission.READ_CONTACTS","\nLevel: DANGEROUS\nReason: Gives access to user's contact list and social graph\n-------\n"},
{"android.permission.WRITE_CONTACTS","\nLevel: DANGEROUS\nReason: Can modify or delete contact entries\n-------\n"},
{"android.permission.GET_ACCOUNTS","\nLevel: MODERATE\nReason: Can access account credentials and sync info\n-------\n"},
{"android.permission.RECORD_AUDIO","\nLevel: DANGEROUS\nReason: Allows eavesdropping through microphone\n-------\n"},
{"android.permission.CAMERA","\nLevel: DANGEROUS\nReason: Can take photos/videos without user's knowledge\n-------\n"},
{"android.permission.READ_PHONE_STATE","\nLevel: MODERATE\nReason: Access to phone number IMEI, call status\n-------\n"},
{"android.permission.CALL_PHONE","\nLevel: DANGEROUS\nReason: Allows calling numbers directly (can be used in scams)\n-------\n"},
{"android.permission.READ_CALL_LOG","\nLevel: DANGEROUS\nReason: Can access user's call history and logs\n-------\n"},
{"android.permission.WRITE_CALL_LOG","\nLevel: DANGEROUS\nReason:Can modify call log data\n-------\n"},
{"android.permission.ACCESS_FINE_LOCATION","\nLevel: DANGEROUS\nReason: Can track user's precise location\n-------\n"},
{"android.permission.ACCESS_COARSE_LOCATION","\nLevel: MODERATE\nReason: Can track user's approximate location\n-------\n"},
{"android.permission.READ_EXTERNAL_STORAGE","\nLevel: DANGEROUS\nReason: Can read all user files (photos, docs, etc.)\n-------\n"},
{"android.permission.WRITE_EXTERNAL_STORAGE","\nLevel: DANGEROUS\nReason: Can modify or delete files on external storage\n-------\n"},
{"android.permission.INTERNET","\nLevel:MODERATE\nReason: Allows network access; dangerous when combined with data permissions\n-------\n"},
{"android.permission.SYSTEM_ALERT_WINDOW","\nLevel: DANGEROUS\nReason: Can draw overlays (used in phishing/overlay attacks)\n-------\n"},
{"android.permission.BIND_ACCESSIBILITY_SERVICE","\nLevel: DANGEROUS\nReason: Can control device input/output — extremely powerful\n-------\n"},
{"android.permission.REQUEST_INSTALL_PACKAGES","\nLevel: MODERATE\nReason: Can install new apps from unknown sources\n-------\n"},
{"android.permission.VIBRATE","\nLevel: LOW\nReason: Used to trigger vibrations; no access to sensitive data\n-------\n"},
{"android.permission.WAKE_LOCK","\nLevel: LOW,Keeps screen awake; minor battery risk, no data access\n-------\n"},
{"android.permission.RECEIVE_BOOT_COMPLETED","\nLevel: MODERATE\nReason: Starts app after boot; can be used for stealthy persistence\n-------\n"}
    };
    //if ((strcmp(a, "permission.txt")) == 0) to be used in a different file
    //checks if the file is permission.txt
    while(fgets(perm, PATH_MAX-1, file))
    {
        //reads the file line by line
        if (strstr(perm, "android:name=\"") == NULL)
        {
            perror("\"android.name\" could not be found");
        }
        else
        {
            
            ptr = strstr(perm, "android:name=\"");//returns a pointer to the character after android.nam...
            ptr += 14;
            char *end;
            if (end = strchr(ptr, '"'))
            {
                //splits it off at the end 
                *end = '\0';
                //printf("%s", ptr);
                for (int i = 1; i < 24; i++)
                {
                    if ((log = fopen("log.txt", "a+")) == NULL)
                    {
                        perror("No log file");
                    }
                    if (strcmp(permission[i], ptr)== 0)
                    {
                        
                        int offset = 0;
                        char temp[keep];
                        memcpy(temp + offset, header_perm, strlen(header_perm));
                        offset += strlen(header_perm);
                        memcpy(temp + offset, permission[i], strlen(permission[i]));
                        offset += strlen(permission[i]);
                        memcpy(temp + offset, rperms[i].level, strlen(rperms[i].level));
                        offset += strlen(rperms[i].level);
                        //memcpy(temp + offset, dang_perm, strlen(dang_perm));
                        //offset += strlen(dang_perm);
                        
                        fwrite(temp, sizeof(char), offset, log);
                        fclose(log);
                        
                        
                    }
                }
            }
        }
    }
    fclose(file);

}