#include "main.h"
//extern char buffer[PATH_MAX];
/*
Over here we analyse the android manifest file for risky permissions and flags
*/
#define keep 10000
char* replace_str(const char *r);
const char *permission[18] = {"android.permission.SEND_SMS", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS ", "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS", "android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_COARSE_LOCATION", "android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW ", "android.permission.REQUEST_INSTALL_PACKAGES",
"android.permission.INSTALL_PACKAGES", "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"};


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


void tag_perm(char *a)
{
    
    FILE *file = fopen(a, "rb");
    FILE *log;
    char perm[PATH_MAX];

    if (file == NULL)
    {
        perror("File could not be read\n");
    }
    char *header_perm = "Pemission: "; 
    char *dang_perm = "\nRisk Level: Dangerous\nReason: Allows this and that(just testing)\n--------\n";
    char *mid_perm = "\nRisk Level: Moderarately\nReason: Allows this and that(just testing)\n--------\n";
    char *low_perm = "\nRisk Level: Low-level\nReason: Allows this and that(just testing)\n--------\n";
    char *ptr = perm;
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
                for (int i = 0; i < 13; i++)
                {
                    if ((log = fopen("log.txt", "a+")) == NULL)
                    {
                        perror("No log file");
                    }
                    if (strcmp(permission[i], ptr)== 0)
                    {
                        
                        int offset = 0;
                        char temp[keep];
                        if(i >= 0 && i < 10)
                        {
                            memcpy(temp + offset, header_perm, strlen(header_perm));
                            offset += strlen(header_perm);
                            memcpy(temp + offset, permission[i], strlen(permission[i]));
                            offset += strlen(permission[i]);
                            memcpy(temp + offset, dang_perm, strlen(dang_perm));
                            offset += strlen(dang_perm);
                            
                            fwrite(temp, sizeof(char), offset, log);
                            fclose(log);
                        }
                        if(i >= 10 && i < 15)
                        {
                            memcpy(temp + offset, header_perm, strlen(header_perm));
                            offset += strlen(header_perm);
                            memcpy(temp + offset, permission[i], strlen(permission[i]));
                            offset += strlen(permission[i]);
                            memcpy(temp + offset, mid_perm, strlen(mid_perm));
                            offset += strlen(mid_perm);
                            
                            fwrite(temp, sizeof(char), offset, log);
                            fclose(log);
                        }
                        if(i >= 15)
                        {
                            memcpy(temp + offset, header_perm, strlen(header_perm));
                            offset += strlen(header_perm);
                            memcpy(temp + offset, permission[i], strlen(permission[i]));
                            offset += strlen(permission[i]);
                            memcpy(temp + offset, low_perm, strlen(low_perm));
                            offset += strlen(low_perm);
                            
                            fwrite(temp, sizeof(char), offset, log);
                            fclose(log);
                        }
                    }
                }
            }
        }
    }
    fclose(file);

}