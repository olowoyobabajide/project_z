/**
 * 
 * This is the rule engine function for the dex
 * 
*/
#include "main.h"
/**
 * @brief Defines the informational part of a security rule.
 *
 * This struct holds the category and description for a threat.
 * It is used for organizing and logging the findings of the analysis engine.
 */
typedef struct {
    /** @brief The high-level category of the threat */
    const char *category;

    /** @brief A description of the rule and the potential threat. */
    const char *description;

} SecurityRuleInfo;

/**
 * @brief A database of security rules with their categories and descriptions.
 *
 * This array serves as a central repository for all the threats the scanner
 * looks for. The final entry is a "sentinel" with NULL members to mark

 * the end of the array, allowing for safe iteration.
 */
SecurityRuleInfo rule_info_database[] = {

    /* *************************************************************** */
    /* ************* Tier 1: Critical-Priority Rules ***************** */
    /* *************************************************************** */
    {
        .category = "Financial (Overlay)",
        .description = "CRITICAL: App uses Accessibility Services. This can be used to read the screen, intercept user input, and draw over other apps to steal credentials."
    },
    {
        .category = "Persistence & Evasion",
        .description = "CRITICAL: App contains a component that can automatically start on device boot, allowing it to run silently in the background."
    },
    {
        .category = "Surveillance (Notifications)",
        .description = "CRITICAL: App can read the content of all notifications, potentially intercepting private messages, 2FA codes, and banking alerts."
    },
    {
        .category = "Dynamic Code Execution",
        .description = "CRITICAL: App can download and execute new, unverified code after installation, completely bypassing static analysis."
    },

    /* *************************************************************** */
    /* ************* Tier 2: High-Priority Rules ********************* */
    /* *************************************************************** */
    {
        .category = "Ransomware Pattern",
        .description = "HIGH: App shows a pattern of file encryption and UI locking capabilities, characteristic of ransomware."
    },
    {
        .category = "Spyware Pattern",
        .description = "HIGH: App combines surveillance capabilities (camera, mic, location) with networking, indicating potential to exfiltrate sensitive data."
    },
    {
        .category = "Code Evasion (Reflection)",
        .description = "HIGH: App uses reflection to potentially hide calls to dangerous APIs, making its true behavior difficult to detect."
    },
    {
        .category = "Anti-Analysis & Emulation",
        .description = "HIGH: App contains code to detect if it is running in a sandbox or emulator, a common technique for malware to evade analysis."
    },
    {
        .category = "Command Execution",
        .description = "HIGH: App can execute arbitrary shell commands on the device."
    },

    /* *************************************************************** */
    /* ************* Tier 3: Medium-Priority Rules ******************* */
    /* *************************************************************** */
    {
        .category = "Data Exfiltration",
        .description = "MEDIUM: App contains networking classes and may be sending sensitive device identifiers."
    },
    {
        .category = "Surveillance (App Usage)",
        .description = "MEDIUM: App can monitor the user's other application usage habits."
    },
    {
        .category = "Surveillance (Clipboard)",
        .description = "MEDIUM: App can read or modify the contents of the system clipboard, potentially stealing copied data."
    },
    {
        .category = "Developer Leftovers",
        .description = "MEDIUM: App references the Android logging framework in combination with sensitive keywords (password, token), indicating a potential information leak."
    },
    {
        .category = "Unsecured WebView",
        .description = "MEDIUM: App uses a WebView with a JavaScript interface enabled, which can be a vector for remote attacks if not secured."
    },
    {
        .category = "Financial (SMS)",
        .description = "MEDIUM: App has components to listen for system events and references SMS APIs, which could be used for fraud or spying."
    },
    {
        .category = "Rooting / Privilege Escalation",
        .description = "MEDIUM: App contains strings related to gaining root access."
    },
    {
        .category = "Weak Cryptography",
        .description = "MEDIUM: App references known weak or insecure cryptographic modes or algorithms."
    },

    // A "sentinel" value to mark the end of the array.
    { .category = NULL, .description = NULL }
};

void analyseDex(
    char **str, int str_count,
    char **typ, int typ_count,
    char **class, int class_count,
    char **method, int method_count,
    char **meth_class, int meth_class_count,
    char **super_class, int super_class_count
    /*uint16_t *code_byte,
    uint32_t code_byte_count*/
);

void analyseDex(
    char **str, int str_count,
    char **typ, int typ_count,
    char **class, int class_count,
    char **method, int method_count,
    char **meth_class, int meth_class_count,
    char **super_class, int super_class_count
    /*uint16_t *code_byte,
    uint32_t code_byte_count*/
){

    FILE *log;

    if((log = fopen("dex_analysis.txt", "w")) == NULL){
        fprintf(stderr, "Could not analyse file\n");
        return;
    }
    printf("[Starting Rule Engine...]\n");
    printf("%s, %s\n", __TIME__,__DATE__);
    
    for(uint32_t i = 0; i < super_class_count; i++){
        if(strstr(super_class[i], "Landroid/accessibilityservice/AccessibilityService;")){
            fprintf(log, "%s, %s\n", rule_info_database[0].category, rule_info_database[0].description);
        }
        else if(strstr(super_class[i], "Landroid/content/BroadcastReceiver;")){
            for(uint32_t j = 0; j < str_count; j++){
                if(strstr(str[j], "android.intent.action.BOOT_COMPLETED")){
                    fprintf(log, "%s, %s\n", rule_info_database[1].category, rule_info_database[1].description);
                }
            }
        }
        else if(strstr(super_class[i], "Landroid/app/NotificationListenerService;")){
            fprintf(log, "%s, %s\n", rule_info_database[2].category, rule_info_database[2].description);
        }
        else if(strstr(super_class[i], "Landroid/content/BroadcastReceiver;")){
            for(uint32_t j = 0; j < str_count; j++){
                if(strstr(str[j], "SmsManager") || strstr(str[j], "sendTextMessage")){
                    fprintf(log, "%s %s\n", rule_info_database[14].category, rule_info_database[14].description);
                }
            }
        }
    }
    for(uint32_t i = 0; i < str_count; i++){
        if(strstr(str[i], "Ldalvik/system/DexClassLoader;") || strstr(str[i], "Ldalvik/system/PathClassLoader;")){
            fprintf(log, "%s, %s\n", rule_info_database[3].category, rule_info_database[3].description);
        }
        if((strcasestr(str[i], "cipher") || strcasestr(str[i], "aes") || strcasestr(str[i], "encrypt")) && (strcasestr(str[i], "File") || strcasestr(str[i], "FileOutputStream")) && strcasestr(str[i], "WindowManager")){
            fprintf(log, "%s, %s\n", rule_info_database[4].category, rule_info_database[4].description);
        }
        if(strcasestr(str[i], "ro.debuggable") || strcasestr(str[i], "generic_x86") || strcasestr(str[i], "sdk_google") || strcasestr(str[i], "com.android.emulator") || strcasestr(str[i], "qemu") || strcasestr(str[i], "vbox") || strcasestr(str[i], "bluestacks")){
            fprintf(log, "%s, %s\n", rule_info_database[7].category, rule_info_database[7].description);
        }
        if(strstr(str[i], "Landroid/app/usage/UsageStatsManager;")){
            fprintf(log, "%s, %s\n", rule_info_database[10].category, rule_info_database[10].description);
        }
        if(strstr(str[i], "Landroid/content/ClipboardManager;")){
            fprintf(log, "%s, %s\n", rule_info_database[11].category, rule_info_database[11].description);
        }
        if(strstr(str[i], "Landroid/util/Log;")){
            for(uint32_t j = 0; j < str_count; j++){
                if(strcasestr(str[j], "password") || strcasestr(str[j], "token") || strcasestr(str[j], "apikey")){
                    fprintf(log, "%s, %s\n", rule_info_database[12].category, rule_info_database[12].description);
                }
            }
        }
        if(strstr(str[i], "/system/bin/su") || strstr(str[i], "/system/bin" ) || strstr(str[i], "/system/xbin") || strcasestr(str[i], "Superuser.apk")){
            fprintf(log, "%s, %s\n", rule_info_database[15].category, rule_info_database[15].description);
            break;
        }
    }
    for (uint32_t i = 0; i < method_count; i++){
        if(method[i] == "Runtime.exec"){
            
        }
    }
    
    for(u_int32_t i = 0; i < meth_class_count; i++){
    // Rule: Command Execution (HIGH)
        /*if(strstr(meth_class[i], "Ljava/lang/Runtime;") && strstr(method[i], "exec")){
            fprintf(log, "%s, %s\n", rule_info_database[8].category, rule_info_database[8].description);               
        }*/
        
        if(strstr(meth_class[i], "addJavascriptInterface")){
            fprintf(log, "%s, %s\n", rule_info_database[13].category, rule_info_database[13].description);               
        }
        /*// Rule: Dynamic Code Execution (HIGH)
        if(((strstr(meth_class[i], "Ljava/lang/System;"))||(strstr(meth_class[i], "Ljava/lang/Runtime;"))) && (strstr(method[i], "loadLibrary")||strstr(method[i], "load"))){
                     fprintf(log, "[%s] %s\n", rule_info_database[3].category, rule_info_database[3].description);
        }*/ // to be added , HIGH
    }
    for(uint32_t i = 0; i < class_count; i++){
        if(strstr(class[i], "Http") || strstr(class[i], "Socket")){
            for(uint32_t j = 0; j < str_count; j++){
                if(strstr(str[j], "MediaRecorder") || strstr(str[j], "AudioRecord") || strstr(str[j], "android.hardware.Camera") || strstr(str[j], "LocationManager")){
                    fprintf(log, "%s, %s\n", rule_info_database[5].category, rule_info_database[5].description);
                }
                // [9] Data Exfiltrat"su"ion
                if(strstr(str[j], "getDeviceId") || strstr(str[j], "android_id")){
                    fprintf(log, "%s %s\n", rule_info_database[9].category, rule_info_database[9].description);
                }  
            }
        }
        if(strstr(class[i], "Ljava/lang/reflect/Method;")){
            for(uint32_t j = 0; j < str_count; j++){
                if(strstr(str[j], "exec") || strstr(str[j], "loadLibrary") || strstr(str[j], "getDeviceId") || strstr(str[j], "sendTextMessage")){
                    fprintf(log, "%s, %s\n", rule_info_database[6].category, rule_info_database[6].description);
                }
            }
        }
    }

    fclose(log);
}