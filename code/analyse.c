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
void parsetag(xmlDocPtr doc, xmlNodePtr cur, FILE *log);
void parsedoc(char *xmlfile, char *root, char *node, FILE *log, void(*xmlfunc)(xmlDocPtr, xmlNodePtr, FILE *log));

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


void parsetag(xmlDocPtr doc, xmlNodePtr cur, FILE *log)
{
    (void)log;
    // Array of tags to process and their corresponding output files
    tag tags[] = {
        {"activity", "activity.xml"},
        {"service", "services.xml"},
        {"receiver", "receiver.xml"},
        {"provider", "providers.xml"}
    };
    
    int num_tags = sizeof(tags) / sizeof(tags[0]);
    FILE *files[num_tags];
    xmlOutputBufferPtr outputs[num_tags];
    xmlNodePtr initial_cur = cur; // Save the starting node
    cur = cur->children;
    //Open all files in write mode to clear them and prepare for writing.
    for (int i = 0; i < num_tags; i++) {
        files[i] = fopen(tags[i].f_tag, "w");
        if (files[i] == NULL) {
            fprintf(stderr, "Error opening file %s\n", tags[i].f_tag);
            // Close already opened files before returning
            for (int j = 0; j < i; j++) {
                if (outputs[j]) {
                    xmlOutputBufferWriteString(outputs[j], "\n</root>\n");
                    xmlOutputBufferClose(outputs[j]);
                }
                if (files[j]) {
                    fclose(files[j]);
                }
            }
            return;
        }
        outputs[i] = xmlOutputBufferCreateFile(files[i], NULL);
        if(outputs[i]) {
            // Write the XML declaration and the opening root tag once per file.
            xmlOutputBufferWriteString(outputs[i], "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>\n");
            xmlOutputBufferWriteString(outputs[i], 
                "<root xmlns:android=\"http://schemas.android.com/apk/res/android\">\n");
        }
    }

    //Iterate through all sibling nodes.
    while (cur != NULL) {
        for (int i = 0; i < num_tags; i++) {
            // Check if the current node name matches one of our target tags.
            if ((!xmlStrcmp(cur->name, (const xmlChar *)tags[i].tag))) {
                // If there's a match, dump the node to the corresponding output buffer.
                if(outputs[i]) {
                    xmlNodeDumpOutput(outputs[i], doc, cur, 0, 1, "UTF-8");
                }
                // A node can only match one tag type, so we can break the inner loop.
                break;
            }
        }
        cur = cur->next; // Move to the next sibling node.
    }

    //Write the closing root tag and close all buffers and files.
    for (int i = 0; i < num_tags; i++) {
        if (outputs[i]) {
            xmlOutputBufferWriteString(outputs[i], "\n</root>\n");
            xmlOutputBufferClose(outputs[i]); // This also flushes the buffer.
        }
        if (files[i]) {
            fclose(files[i]);
        }
    }

    return;
}

void parsedoc(char *xmlfile, char *root, char *node, FILE *log, void(*xmlfunc)(xmlDocPtr, xmlNodePtr, FILE *))
{
    //this function parses the xml document 
    xmlNodePtr cur;
    xmlDocPtr doc = xmlParseFile(xmlfile);

    /*if (log == NULL)
    {
        printf("error\n");
    }*/

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
                xmlfunc(doc, child, log);
            }
            child = child->next;
        }
    }
    xmlFreeDoc(doc);
}

void parseActivity(xmlDocPtr doc, xmlNodePtr cur, FILE *log)
{
    
    /*if (log == NULL)
    {
        perror("No log file");
    }*/

    fprintf(log, "\nActivity Checker\n");
    if((!xmlStrcmp(cur->name, (const xmlChar*)"activity")))
    {

        xmlChar *export = xmlGetProp(cur, (const xmlChar*)"exported");
        xmlChar *actName = xmlGetProp(cur, (const xmlChar*)"name");
        if (export != NULL && actName != NULL && (!xmlStrcmp(export, (const xmlChar*)"true"))){
            
            xmlNodePtr activityNode = cur->children;
            int hasIntentfilter = 0;
            while (activityNode != NULL) 
            {
                //confirms that <ativity> tag has an intent filter
                if((!xmlStrcmp(activityNode->name, (const xmlChar*)"intent-filter"))){
                    hasIntentfilter = 1;
                    xmlNodePtr child = activityNode->xmlChildrenNode;
                    while(child != NULL)
                    {
                        if ((!xmlStrcmp(child->name, (const xmlChar *)"action")) ||
                            !(xmlStrcmp(child->name, (const xmlChar*)"category")) ){
                            xmlChar *actionName = xmlGetProp(child, (const xmlChar*)"name");
                            if(actionName != NULL && (!xmlStrcmp(export, (const xmlChar*)"true")))
                            {
                                fprintf(log, "\nActivity: %s\nIntent-filter: yes\
                                    \nExported: \nPerrmission: None\nRisk Level: Dangerous\n", actionName, export);
                                fprintf(log, "Reason: Exported activity with intent-filter and no access restriction\n-------\n");
                                xmlFree(actionName);
                            }
                            if(actionName != NULL && (!xmlStrcmp(export, (const xmlChar*)"false"))){
                                fprintf(log, "\nActivity: %s\nIntent-filter: yes\
                                    \nExported: \nPerrmission: None\nRisk Level: Safe\n", actionName, export);
                                fprintf(log, "Not exported. Safe\n");
                                xmlFree(actionName);
                            }
                        }
                        child = child->next;
                    }
                }
                activityNode = activityNode->next;

            }
            if(hasIntentfilter == 0){
                fprintf(log, "\nActivity: %s\nIntent-filter: No\
                    \nExported: false\nPermission: None\nRisk Level: Moderate\n", actName);
                fprintf(log, "Reason: Exported activity without an intent-filter. Can be launched by name. Is this necessary?\n-------\n");
            }
            xmlFree(export);
            xmlFree(actName);
        }
        
    }
    
    //fclose(log);
    return;
}

void parseService(xmlDocPtr doc, xmlNodePtr cur, FILE *log)
{

    /*if (log == NULL)
    {
        fprintf(stderr, "Services not available\n");

    }*/
    if ((!xmlStrcmp(cur->name, (const xmlChar*)"service"))){
        xmlChar *servicename = xmlGetProp(cur, (const xmlChar*)"name");
        xmlChar *checkExport = xmlGetProp(cur, (const xmlChar*)"exported");
        xmlChar *checkPermission = xmlGetProp(cur, (const xmlChar*)"permission");
        fprintf(log, "Service: %s\n", servicename);
        fprintf(log, "Exported: %s\n", checkExport);
        xmlChar *reason;
        xmlNodePtr intent;
    
        if (checkExport != NULL){
            if((!xmlStrcmp(checkExport, (const xmlChar*)"true"))){
               intent = cur->children;
                if (checkPermission == NULL)
                {
                    fprintf(log, "Permission: %s\n", checkPermission);
                    reason = "DANGEROUS (Exported Without Permission)\n";
                    while (intent != NULL)
                    {
                        if((!xmlStrcmp(intent->name, (const xmlChar*)"intent-filter")))
                        {
                            fprintf(log, "Intent filter: YES\n");
                            fprintf(log, "Reason: %s\n------\n", reason);
                        }
                        intent = intent->next;
                    }
                }
                else{
                    fprintf(log, "Permission: %s", checkPermission);
                    reason = "SAFE (Exported but protected)\n";
                    while (intent != NULL)
                    {
                        if((!xmlStrcmp(intent->name, (const xmlChar*)"intent-filter")))
                        {
                            fprintf(log, "Intent filter: YES\n");
                            fprintf(log, "Reason: %s\n------\n", reason);
                        }
                        intent = intent->next;
                    }
                }
            }
            else{
                //intent = cur->children;
                fprintf(log, "Permission: None\n");
                while(intent != NULL)
                {
                    if((!xmlStrcmp(intent->name, (const xmlChar*)"intent-filter")))
                    {
                        fprintf(log, "Intent filter: YES\n");
                        fprintf(log, "Reason: SAFE (Service not exported)\n------\n");
                    }
                    else
                    {
                        fprintf(log, "Intent filter: NO\n");
                        fprintf(log, "Reason: SAFE (Service not exported)\n------\n");
                    }
                    intent = intent->next;   
                }
            }
        }
        /**
         * there is to be a check for when 'exported' is NULL
         * but, it is for android versions <=12
         * let's skip it for now
         */
        xmlFree(servicename);
        xmlFree(checkExport);
        xmlFree(checkPermission);
    }
    //fclose(log);
}

typedef struct {
    /**
     * this struct contains the name & reasons for 
     * different the actions in the receiver tag
     */
    char *intent;
    char *intentRisk;
} actionIntent;

void parseReceiver(xmlDocPtr doc, xmlNodePtr cur, FILE *log)
{
    /*if ((log = fopen("log.txt", "a+")) == NULL)
    {
        fprintf(stderr, "Services not available\n");

    }*/

    actionIntent actIntent[] = {"", "", "android.intent.action.BOOT_COMPLETED", "Risk: malware persistence risk.",
"android.intent.action.QUICKBOOT_POWERON","same risk as BOOT_COMPLETED",
"android.provider.Telephony.SMS_RECEIVED","phishing/spam/code execution",
"android.provider.Telephony.WAP_PUSH_RECEIVED" "malicious links/files",
"android.intent.action.DATA_SMS_RECEIVED", "hidden triggers",
"android.intent.action.PACKAGE_ADDED", "install event",
"android.intent.action.PACKAGE_REMOVED","uninstall event",
"android.intent.action.PACKAGE_REPLACED","update event",
"android.net.conn.CONNECTIVITY_CHANGE","forces unwanted behaviour",
"android.net.wifi.WIFI_STATE_CHANGED","Wi-Fi on/off events",
"android.net.wifi.SCAN_RESULTS","Wi-Fi scan results",
"android.intent.action.MEDIA_MOUNTED" "attacker-controlled storage",
"android.intent.action.NEW_OUTGOING_CALL","Spoof outgoing calls, hijack dialler",
"android.intent.action.USER_PRESENT","device unlock events",
"android.intent.action.TIME_TICK","abuse for DoS/battery drain"};

    if((!xmlStrcmp(cur->name, (const xmlChar*)"receiver")))
    {
        xmlChar *receiverName = xmlGetProp(cur, (const xmlChar*)"name");
        xmlChar *export = xmlGetProp(cur, (const xmlChar*)"exported");
        xmlChar *checkPermission = xmlGetProp(cur, (const xmlChar*)"permission");

        fprintf(log, "Receiver\n");
        fprintf(log, "Receiver name: %s\n", receiverName);
        xmlNodePtr intent;

        if(export != NULL)
        {
            if((!xmlStrcmp(export, (const xmlChar*)"true"))){
                fprintf(log, "Exported: %s\n", export);
                intent = cur->children;
                if (checkPermission == NULL)
                {
                    fprintf(log, "Permission: None\n");
                    while(intent != NULL)
                    {
                        if((!xmlStrcmp(intent->name, (const xmlChar*)"intent-filter"))){
                            fprintf(log, "Intent-filter: Yes\n");
                            xmlNodePtr action = intent->children;
                            xmlChar *actionName = xmlGetProp(action, (const xmlChar*)"name");
                            while(action != NULL){
                                if ((!xmlStrcmp(action->name, (const xmlChar*)"name"))){
                                    for(int i = 1; i < sizeof(actIntent); i++){
                                        fprintf(log, "%s\nRisk: %s\n", actIntent->intent, actIntent->intentRisk);
                                        fprintf(log, "------");
                                    }
                                }
                                action = action->next;
                            }
                            if (actionName) xmlFree(actionName);
                        }
                        intent = intent->next;
                    }

                }
                else{
                    fprintf(log, "Permission: %s\n", checkPermission);
                    fprintf(log, "Risk: Moderate - only apps signed with the same key (or granted this permission explicitly) can send the broadcast\n");
                }
            }
            else{
                 fprintf(log, "Exported: %s", export);
                 fprintf(log, "Risk-level: Low - It's safe because only the app can send broadcasts internally.\n");
                 fprintf(log, "------");
            }
        }
        if(receiverName) xmlFree(receiverName);
        if(export) xmlFree(export);
        if(checkPermission) xmlFree(receiverName);
    }
    
}

void parseProvider(xmlDocPtr, xmlNodePtr cur, FILE *log)
{
    if ((!xmlStrcmp(cur->name, (const xmlChar*)"provider"))){
        xmlChar *providerName = xmlGetProp(cur, (const xmlChar*)"name");
        xmlChar *exported = xmlGetProp(cur, (const xmlChar*)"exported");
        xmlChar *readPermission = xmlGetProp(cur, (const xmlChar*)"readPermission");
        xmlChar *writePermission = xmlGetProp(cur, (const xmlChar*)"writePermission");
        xmlChar *grantUri = xmlGetProp(cur, (const xmlChar*)"grantUriPermissions");
        xmlChar *authorities = xmlGetProp(cur, (const xmlChar*)"authorities");
        xmlNodePtr grantPermission = cur->children;

        if(exported != NULL)
        {
            if((!xmlStrcmp(exported, (const xmlChar *)"true"))){
                fprintf(log, "Provider name: %s\n", providerName);
                if(readPermission == NULL && writePermission != NULL){
                    fprintf(log, "Read Permission: None\n");
                    fprintf(log, "Write Permission: None\n");
                }
                else{
                    fprintf(log, "Read Permission: %s\n", readPermission);
                    fprintf(log, "Write Permission: %s\n", writePermission);
                }
                if(grantUri != NULL){
                    if ((!xmlStrcmp(grantUri, (const xmlChar*)"true"))){
                        fprintf(log, "Grant URI Permission: %s.\n", grantUri);
                        while (grantPermission != NULL){
                            if((!xmlStrcmp(grantPermission->name, (const xmlChar*)"path-permission"))){
                                fprintf(log, "HIGH:'grantUripermissions' used without path restrictions\n");
                            }
                            else{
                                fprintf(log, "OK:'grantUripermissions' restricted with path permission\n");
                            }
                        }
                    }
                }
                if(authorities != NULL){
                    fprintf(log, "Authorities: %s\n", authorities);
                }
                    
            }
            else{
                fprintf(log, "Provider name: %s\n", providerName);
                fprintf(log, "Exported: %s\n", exported);
                fprintf(log, "SAFE: Provider not exported\n------\n");
            }
        }
        if(providerName) xmlFree(providerName);
        if(exported) xmlFree(exported);
        if(readPermission) xmlFree(readPermission);
        if(writePermission) xmlFree(writePermission);
        if(grantUri) xmlFree(grantUri);
        if(authorities) xmlFree(authorities);
    }
}

int analyse_per(char *a)
{
    char perm[PATH_MAX];
    bool inside_intent = false;
    bool inside_tag = false;
    FILE *AndroidManifest, *file_point[2];

    FILE *log = fopen("log.txt", "w");
    if (log == NULL){
        perror("The AndroidManifest does not exist\n");
        return EXIT_FAILURE;
    }
    
    parsedoc("AndroidManifest.xml", "manifest", "application", log, parsetag);
    parsedoc("activity.xml", "root", "activity", log,  parseActivity);
    parsedoc("services.xml", "root", "service", log, parseService);
    parsedoc("receiver.xml", "root", "receiver", log, parseReceiver);
    

    tag tags[] = {{"uses-permission", "permission.txt"}, {"application", "app.txt"}};
    
    if ((AndroidManifest = fopen("AndroidManifest.xml", "rb")) == NULL)
    {
        perror("The AndroidManifest does not exist\n");
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
    fclose(log);
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
    if ((log = fopen("log.txt", "w")) == NULL)
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