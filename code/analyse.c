#include "main.h"
#include "src/dep/libxml/parser.h" 
#include "src/dep/libxml/tree.h"
#include "report.h"

void parsetag_permissions(xmlDocPtr doc, xmlNodePtr cur, Report *r);
void parsetag_components(xmlDocPtr doc, xmlNodePtr cur, Report *r);
void parsedoc(char *xml_buffer, char *root, char *node, Report *r, void(*xmlfunc)(xmlDocPtr, xmlNodePtr, Report *));

void parseActivity(xmlDocPtr doc, xmlNodePtr cur, Report *r);
void parseService(xmlDocPtr doc, xmlNodePtr cur, Report *r);
void parseReceiver(xmlDocPtr doc, xmlNodePtr cur, Report *r);
void parseProvider(xmlDocPtr doc, xmlNodePtr cur, Report *r);
void parsePermission(xmlDocPtr doc, xmlNodePtr cur, Report *r);

#define keep 10000

typedef struct{
    char *name;
    char *level;
}rperm;
rperm rperms[] = {{"android.permission.READ_SMS","\nRisk Level: DANGEROUS\nReason: Allows reading of user's private SMS messages\n-------\n"},
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

size_t NUM_PERMISSIONS = sizeof(rperms)/sizeof(rperm);

int analyse_per(char *xml_buffer, Report *r);

void parsetag_permissions(xmlDocPtr doc, xmlNodePtr cur, Report *r)
{
    cur = cur->children;
    while (cur != NULL) {
        if (!xmlStrcmp(cur->name, (const xmlChar *)"uses-permission")) {
            parsePermission(doc, cur, r);
        }
        cur = cur->next;
    }
}

void parsetag_components(xmlDocPtr doc, xmlNodePtr cur, Report *r)
{
    cur = cur->children;
    while (cur != NULL) {
        if (!xmlStrcmp(cur->name, (const xmlChar *)"activity")) {
            parseActivity(doc, cur, r);
        } else if (!xmlStrcmp(cur->name, (const xmlChar *)"service")) {
            parseService(doc, cur, r);
        } else if (!xmlStrcmp(cur->name, (const xmlChar *)"receiver")) {
            parseReceiver(doc, cur, r);
        } else if (!xmlStrcmp(cur->name, (const xmlChar *)"provider")) {
            parseProvider(doc, cur, r);
        }
        cur = cur->next;
    }
}

void parsedoc(char *xml_buffer, char *root, char *node, Report *r, void(*xmlfunc)(xmlDocPtr, xmlNodePtr, Report *))
{
    if (xml_buffer == NULL) return;
    xmlDocPtr doc = xmlReadMemory(xml_buffer, strlen(xml_buffer), "noname.xml", NULL, 0);
    if (doc == NULL) return;
    xmlNodePtr cur = xmlDocGetRootElement(doc);
    if (cur == NULL) { xmlFreeDoc(doc); return; }

    if (xmlStrcmp(cur->name, (const xmlChar *)root)) { xmlFreeDoc(doc); return; }

    if (strcmp(root, node) == 0) {
        xmlfunc(doc, cur, r);
    } else {
        cur = cur->children;
        while (cur != NULL) {
            if (!xmlStrcmp(cur->name, (const xmlChar *)node)) {
                xmlfunc(doc, cur, r);
            }
            cur = cur->next;
        }
    }
    xmlFreeDoc(doc);
}

void parseActivity(xmlDocPtr doc, xmlNodePtr cur, Report *r)
{
    xmlChar *activityName = xmlGetProp(cur, (const xmlChar*)"name");
    xmlChar *exported = xmlGetProp(cur, (const xmlChar*)"exported");
    xmlChar *perm = xmlGetProp(cur, (const xmlChar*)"permission");
    xmlNodePtr intentFilter = cur->children;
    int hasIntentFilter = 0;

    while (intentFilter != NULL) {
        if (!xmlStrcmp(intentFilter->name, (const xmlChar *)"intent-filter")) {
            hasIntentFilter = 1;
            break;
        }
        intentFilter = intentFilter->next;
    }

    int is_exported = 0;
    if (exported != NULL) {
        if (!xmlStrcmp(exported, (const xmlChar *)"true")) is_exported = 1;
    } else if (hasIntentFilter) {
        is_exported = 1;
    }

    if (is_exported && perm == NULL) {
        add_finding(r, FINDING_ACTIVITY, (char*)activityName, "HIGH", "Activity is exported but not protected by any permission.", "Exported without permission", "AndroidManifest.xml", (char*)activityName);
    }

    if (activityName) xmlFree(activityName);
    if (exported) xmlFree(exported);
    if (perm) xmlFree(perm);
}

void parseService(xmlDocPtr doc, xmlNodePtr cur, Report *r)
{
    xmlChar *serviceName = xmlGetProp(cur, (const xmlChar*)"name");
    xmlChar *exported = xmlGetProp(cur, (const xmlChar*)"exported");
    xmlChar *permission = xmlGetProp(cur, (const xmlChar*)"permission");
    
    int is_exported = (exported && !xmlStrcmp(exported, (const xmlChar*)"true"));

    if (is_exported && permission == NULL) {
        add_finding(r, FINDING_SERVICE, (char*)serviceName, "HIGH", "Service is exported but not protected by any permission.", "Exported without permission", "AndroidManifest.xml", (char*)serviceName);
    }

    if (serviceName) xmlFree(serviceName);
    if (exported) xmlFree(exported);
    if (permission) xmlFree(permission);
}

void parseReceiver(xmlDocPtr doc, xmlNodePtr cur, Report *r)
{
    xmlChar *receiverName = xmlGetProp(cur, (const xmlChar*)"name");
    xmlChar *export = xmlGetProp(cur, (const xmlChar*)"exported");
    xmlChar *checkPermission = xmlGetProp(cur, (const xmlChar*)"permission");

    int is_exported = (export && !xmlStrcmp(export, (const xmlChar*)"true"));

    if (is_exported && checkPermission == NULL) {
        add_finding(r, FINDING_RECEIVER, (char*)receiverName, "HIGH", "Broadcast Receiver is exported but not protected by any permission.", "Exported without permission", "AndroidManifest.xml", (char*)receiverName);
    }

    if (receiverName) xmlFree(receiverName);
    if (export) xmlFree(export);
    if (checkPermission) xmlFree(checkPermission);
}

void parseProvider(xmlDocPtr doc, xmlNodePtr cur, Report *r)
{
    xmlChar *providerName = xmlGetProp(cur, (const xmlChar*)"name");
    xmlChar *exported = xmlGetProp(cur, (const xmlChar*)"exported");
    xmlChar *readPermission = xmlGetProp(cur, (const xmlChar*)"readPermission");
    xmlChar *writePermission = xmlGetProp(cur, (const xmlChar*)"writePermission");
    xmlChar *grantUri = xmlGetProp(cur, (const xmlChar*)"grantUriPermissions");

    int is_exported = (exported && !xmlStrcmp(exported, (const xmlChar*)"true"));

    if (is_exported) {
        if (readPermission == NULL || writePermission == NULL) {
             add_finding(r, FINDING_PROVIDER, (char*)providerName, "HIGH", "Content Provider is exported but lacks read or write permissions.", "Exported with missing permissions", "AndroidManifest.xml", (char*)providerName);
        }
        if (grantUri && !xmlStrcmp(grantUri, (const xmlChar*)"true")) {
             add_finding(r, FINDING_PROVIDER, (char*)providerName, "MEDIUM", "Content Provider allows URI permission granting, which can be risky.", "grantUriPermissions=true", "AndroidManifest.xml", (char*)providerName);
        }
    }

    if (providerName) xmlFree(providerName);
    if (exported) xmlFree(exported);
    if (readPermission) xmlFree(readPermission);
    if (writePermission) xmlFree(writePermission);
    if (grantUri) xmlFree(grantUri);
}

void parsePermission(xmlDocPtr doc, xmlNodePtr cur, Report *r){
    xmlChar* permission = xmlGetProp(cur, (const xmlChar*)"name");
    if (permission != NULL) {
        for (int i = 0; i < NUM_PERMISSIONS; i++) {
            if (strcmp(rperms[i].name, (char*)permission) == 0) {
                add_finding(r, FINDING_PERMISSION, (char*)permission, rperms[i].level, "Requested in Manifest", "", "AndroidManifest.xml", (char*)permission);
            }
        }
    }
    if (permission) xmlFree(permission);
}

int analyse_per(char *xml_buffer, Report *r)
{
    if (xml_buffer == NULL) return EXIT_FAILURE;

    parsedoc(xml_buffer, "manifest", "manifest", r, parsetag_permissions); 
    parsedoc(xml_buffer, "manifest", "application", r, parsetag_components);

    free(xml_buffer);
    return 0;
}
