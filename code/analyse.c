#include "main.h"
#include <stdbool.h>
#include <libxml/parser.h> 
#include <libxml/tree.h>

//gcc main.c analyse.c -o fs $(pkg-config --cflags --libs libxml-2.0)  compiling

//extern char buffer[PATH_MAX];
/*
Over here we analyse the android manifest file for risky permissions and flags
*/
#define keep 10000

const char *permission[24] = {" ","android.permission.READ_SMS","android.permission.SEND_SMS","android.permission.RECEIVE_SMS",
"android.permission.READ_CONTACTS","android.permission.WRITE_CONTACTS","android.permission.GET_ACCOUNTS",
"android.permission.RECORD_AUDIO","android.permission.CAMERA","android.permission.READ_PHONE_STATE",
"android.permission.CALL_PHONE","android.permission.READ_CALL_LOG","android.permission.WRITE_CALL_LOG",
"android.permission.ACCESS_FINE_LOCATION","android.permission.ACCESS_COARSE_LOCATION","android.permission.READ_EXTERNAL_STORAGE",
"android.permission.WRITE_EXTERNAL_STORAGE","android.permission.INTERNET","android.permission.SYSTEM_ALERT_WINDOW",
"android.permission.BIND_ACCESSIBILITY_SERVICE","android.permission.REQUEST_INSTALL_PACKAGES",
"android.permission.VIBRATE","android.permission.WAKE_LOCK","android.permission.RECEIVE_BOOT_COMPLETED"};
void parsetag(xmlDocPtr doc, xmlNodePtr cur);
void parsedoc(char *xmlfile, char *root, char *node, void(*xmlfunc)(xmlDocPtr, xmlNodePtr));

typedef struct tag{
    //A struct for the the tags activity, services...
    char *tag;
    char *f_tag;
}tag;
typedef struct reason_perms{
    //This struct details about the permissions found
    char *name;
    char *level;
}rperm;


void parsetag(xmlDocPtr doc, xmlNodePtr cur)
{
    //parsing the tag. Checking for each nested node under <application>
    //xmlBufferPtr buf = xmlBufferCreate();
    FILE *file[4];

    tag tags[] = {{"activity", "activity.xml"}, {"service", "services.xml"},
    {"receiver", "receiver.xml"}, {"provider", "providers.xml"}};
    xmlOutputBufferPtr output;
    //cur = cur->xmlChildrenNode;

    while (cur != NULL)
    {
        for(int i = 0; i < 4; i++){
            if ((!xmlStrcmp(cur->name, (const xmlChar *)tags[i].tag))){
                if ((file[i] = fopen(tags[i].f_tag, "a+"))/* != NULL*/){
                    output = xmlOutputBufferCreateFile(file[i], NULL);
                    if(output)
                    {
                        /*xmlOutputBufferWriteString(output, 
                            "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>\n");
                        xmlOutputBufferWriteString(output, "<root>\n");*/
                        xmlNodeDumpOutput(output, doc, cur, 0, 1, "UTF-8");
                        //xmlOutputBufferWriteString(output, "\n</root>\n");
                        xmlOutputBufferClose(output);
                    }
                }
            }
        }
        cur = cur->next;
    }
    for (int i = 0; i > 0; i++)
    {
        if((file[i] = fopen(tags[i].f_tag, "a"))){
            fprintf(file[i], "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>\n");
        }
    }
    return;
}

void parsedoc(char *xmlfile, char *root, char *node, void(*xmlfunc)(xmlDocPtr, xmlNodePtr))
{
    //this function parses the xml document 
    xmlNodePtr cur;
    xmlDocPtr doc = xmlParseFile(xmlfile);

    if(doc == NULL)
    {
        fprintf(stderr, "Document not parsed successfully\n");
        xmlFreeDoc(doc);
        return;
    }

    cur = xmlDocGetRootElement(doc);

    if (cur == NULL)
    {
        fprintf(stderr, "Empty Document\n");
        xmlFreeDoc(doc);
        return;
    }
    if (!xmlStrcmp(cur->name, (const xmlChar *)root))
    {
        xmlNodePtr child = cur->xmlChildrenNode;
        while(child != NULL)
        {
            if((!xmlStrcmp(child->name, (const xmlChar *)node)))
            {
                xmlfunc(doc, child->xmlChildrenNode);
            }
            child = child->next;
        }
    }
    xmlFreeDoc(doc);
}

void parseActivity(xmlDocPtr doc, xmlNodePtr cur)
{
    //parsing the <activity>tag and logging it


    while (cur != NULL)
    {
        
        if ((!xmlStrcmp(cur->name, (const xmlChar *)"action"))){
            xmlChar *actionName = xmlGetProp(cur, (const xmlChar *)"action:name");
            if (actionName){
                printf("%s\n", actionName);
            }
        }
        cur = cur->next;
    }

    return;
}
int analyse_per(char *a)
{
    char perm[PATH_MAX];
    bool inside_intent = false;
    bool inside_tag = false;
    FILE *AndroidManifest;
    FILE *file_point[2];

    parsedoc("AndroidManifest.xml", "manifest", "application", parsetag);
    //parsedoc("activity.xml", "activity", "intent-filter", parseActivity);

    tag tags[] = {{"uses-permission", "permission.txt"}, {"application", "app.txt"}};
    
    if ((AndroidManifest = fopen("AndroidManifest.xml", "rb")) == NULL)
    {
        perror("The AndroidManifest file could not be open");
        return EXIT_FAILURE;
    }
    while(fgets(perm, PATH_MAX-1, AndroidManifest))
    {
        for (int i = 0; i < 2; i++)
            if (strstr(perm, tags[i].tag) && (file_point[i] = fopen(tags[i].f_tag, "a+")) != NULL)
            {
                fprintf(file_point[i], "%s", perm);
            }

    }
    fclose(AndroidManifest);
    return 0;
}


void tag_perm(char *a)
{
    
    FILE *file;
    FILE *log;
    char perm[PATH_MAX];

    if ((file = fopen(a, "rb")) == NULL)
    {
        perror("File could not be read\n");
    }
    
    char *ptr = perm;
    char *header_perm = "Permission: ";
    rperm rperms[] = {{" "," "},
{"android.permission.READ_SMS","\nRisk Level: DANGEROUS\nReason: Allows reading of user's private SMS messages\n-------\n"},
{"android.permission.SEND_SMS","\nRisk Level: DANGEROUS\nReason: Can send SMS without user consent (used for scams)\n-------\n"},
{"android.permission.RECEIVE_SMS","\nRisk Level: DANGEROUS\nReason: Can intercept incoming SMS (used for OTP theft)\n-------\n"},
{"android.permission.READ_CONTACTS","\nRisk Level: DANGEROUS\nReason: Gives access to user's contact list and social graph\n-------\n"},
{"android.permission.WRITE_CONTACTS","\nRisk Level: DANGEROUS\nReason: Can modify or delete contact entries\n-------\n"},
{"android.permission.GET_ACCOUNTS","\nRisk Level: MODERATE\nReason: Can access account credentials and sync info\n-------\n"},
{"android.permission.RECORD_AUDIO","\nRisk Level: DANGEROUS\nReason: Allows eavesdropping through microphone\n-------\n"},
{"android.permission.CAMERA","\nRisk Level: DANGEROUS\nReason: Can take photos/videos without user's knowledge\n-------\n"},
{"android.permission.READ_PHONE_STATE","\nRisk Level: MODERATE\nReason: Access to phone number IMEI, call status\n-------\n"},
{"android.permission.CALL_PHONE","\nRisk Level: DANGEROUS\nReason: Allows calling numbers directly (can be used in scams)\n-------\n"},
{"android.permission.READ_CALL_LOG","\nRisk Level: DANGEROUS\nReason: Can access user's call history and logs\n-------\n"},
{"android.permission.WRITE_CALL_LOG","\nRisk Level: DANGEROUS\nReason:Can modify call log data\n-------\n"},
{"android.permission.ACCESS_FINE_LOCATION","\nRisk Level: DANGEROUS\nReason: Can track user's precise location\n-------\n"},
{"android.permission.ACCESS_COARSE_LOCATION","\nRisk Level: MODERATE\nReason: Can track user's approximate location\n-------\n"},
{"android.permission.READ_EXTERNAL_STORAGE","\nRisk Level: DANGEROUS\nReason: Can read all user files (photos, docs, etc.)\n-------\n"},
{"android.permission.WRITE_EXTERNAL_STORAGE","\nRisk Level: DANGEROUS\nReason: Can modify or delete files on external storage\n-------\n"},
{"android.permission.INTERNET","\nRisk Level:MODERATE\nReason: Allows network access; dangerous when combined with data permissions\n-------\n"},
{"android.permission.SYSTEM_ALERT_WINDOW","\nRisk Level: DANGEROUS\nReason: Can draw overlays (used in phishing/overlay attacks)\n-------\n"},
{"android.permission.BIND_ACCESSIBILITY_SERVICE","\nRisk Level: DANGEROUS\nReason: Can control device input/output — extremely powerful\n-------\n"},
{"android.permission.REQUEST_INSTALL_PACKAGES","\nRisk Level: MODERATE\nReason: Can install new apps from unknown sources\n-------\n"},
{"android.permission.VIBRATE","\nRisk Level: LOW\nReason: Used to trigger vibrations; no access to sensitive data\n-------\n"},
{"android.permission.WAKE_LOCK","\nRisk Level: LOW,Keeps screen awake; minor battery risk, no data access\n-------\n"},
{"android.permission.RECEIVE_BOOT_COMPLETED","\nRisk Level: MODERATE\nReason: Starts app after boot; can be used for stealthy persistence\n-------\n"}
    };
    if ((log = fopen("log.txt", "a+")) == NULL)
    {
        perror("No log file");
    }
    //if ((strcmp(a, "permission.txt")) == 0) to be used in a different file
    while(fgets(perm, PATH_MAX-1, file))//reads the file line by line
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
                    
                    fwrite(temp, sizeof(char), offset, log);
                    
                }
            }
        }
    }
    fclose(log);
    fclose(file);

}

int tag_act(char *a)
{
    FILE *file;
    FILE *act;

    if((file = fopen(a, "rb")) == NULL)
    {
        perror("Cannot read activity.txt");
    }
    if ((act = fopen("log.txt", "a+")) == NULL)
    {
        perror("The log file is inaccessbile");
        return EXIT_FAILURE;
    }
    char *hehe = "Activity: ";
    char perm[PATH_MAX];
    char *ptr = perm;
    while(fgets(perm, PATH_MAX-1, file))//reads the file line by line
    {
        
        if((ptr = strstr(perm, "android:name=\""))!= NULL)//returns a pointer to the character after android.nam...
        {
            ptr += 14;
            char *end;
            if (end = strchr(ptr, '"'))
            {
                //splits it off at the end 
                *end = '\0';
                //printf("%s", ptr);
                        
                int offset = 0;
                char temp[keep];

                memcpy(temp + offset, hehe, strlen(hehe));
                offset += strlen(hehe);
                memcpy(temp + offset, ptr, strlen(ptr));
                offset += strlen(ptr);
                
                fwrite(temp, sizeof(char), offset, act);
            }
        }
    }
    fclose(act);
    fclose(file);
}