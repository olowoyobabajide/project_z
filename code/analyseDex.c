/*
 * Copyright (c) 2026 olowoyobabajide <olowoyobabajide@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

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
    char **super_class, int super_class_count,
    Report *report,
    const char *filename
){
    // Evidence strings (NULL means not found)
    char *evidence_accessibility = NULL;
    char *evidence_broadcast_boot = NULL;
    char *evidence_notification_listener = NULL;
    char *evidence_dex_loader = NULL;
    char *evidence_crypto_file = NULL; // Combination
    char *evidence_camera_mic_socket = NULL; // Combination
    char *evidence_reflection_exec = NULL; // Combination
    char *evidence_emulator_check = NULL;
    char *evidence_runtime_exec = NULL;
    char *evidence_usage_stats = NULL;
    char *evidence_clipboard = NULL;
    char *evidence_log_secrets = NULL; // Combination
    char *evidence_js_interface = NULL;
    char *evidence_sms_manager = NULL;
    char *evidence_root = NULL;

    // Helper evidence
    char *ev_broadcast_receiver = NULL;
    char *ev_boot_completed = NULL;
    char *ev_sms_send = NULL;
    char *ev_log_util = NULL;
    char *ev_sensitive_string = NULL;
    char *ev_http_socket = NULL;
    char *ev_media_hardware = NULL;
    char *ev_reflection = NULL;
    char *ev_exec_cmd = NULL;
    char *ev_cipher = NULL;
    char *ev_file_io = NULL;
    char *ev_window_manager = NULL;

    // 1. Scan Super Classes
    for(uint32_t i = 0; i < super_class_count; i++){
        if(!super_class[i]) continue;
        if(strstr(super_class[i], "Landroid/accessibilityservice/AccessibilityService;")) evidence_accessibility = super_class[i];
        if(strstr(super_class[i], "Landroid/content/BroadcastReceiver;")) ev_broadcast_receiver = super_class[i];
        if(strstr(super_class[i], "Landroid/app/NotificationListenerService;")) evidence_notification_listener = super_class[i];
    }

    // 2. Scan Strings
    for(uint32_t i = 0; i < str_count; i++){
        if(!str[i]) continue;
        
        if(strstr(str[i], "android.intent.action.BOOT_COMPLETED")) ev_boot_completed = str[i];
        if(strstr(str[i], "SmsManager") || strstr(str[i], "sendTextMessage")) ev_sms_send = str[i];
        
        if(strstr(str[i], "Ldalvik/system/DexClassLoader;") || strstr(str[i], "Ldalvik/system/PathClassLoader;")) evidence_dex_loader = str[i];

        if(strcasestr(str[i], "cipher") || strcasestr(str[i], "aes") || strcasestr(str[i], "encrypt")) ev_cipher = str[i];
        if(strcasestr(str[i], "File") || strcasestr(str[i], "FileOutputStream")) ev_file_io = str[i];
        if(strcasestr(str[i], "WindowManager")) ev_window_manager = str[i];

        if(strcasestr(str[i], "ro.debuggable") || strcasestr(str[i], "generic_x86") || strcasestr(str[i], "sdk_google") || 
           strcasestr(str[i], "com.android.emulator") || strcasestr(str[i], "qemu") || strcasestr(str[i], "vbox") || strcasestr(str[i], "bluestacks")) 
           evidence_emulator_check = str[i];

        if(strstr(str[i], "Landroid/app/usage/UsageStatsManager;")) evidence_usage_stats = str[i];
        if(strstr(str[i], "Landroid/content/ClipboardManager;")) evidence_clipboard = str[i];

        if(strstr(str[i], "Landroid/util/Log;")) ev_log_util = str[i];
        if(strcasestr(str[i], "password") || strcasestr(str[i], "token") || strcasestr(str[i], "apikey")) ev_sensitive_string = str[i];

        if(strstr(str[i], "/system/bin/su") || strstr(str[i], "/system/bin" ) || strstr(str[i], "/system/xbin") || strcasestr(str[i], "Superuser.apk")) evidence_root = str[i];

        if(strstr(str[i], "MediaRecorder") || strstr(str[i], "AudioRecord") || strstr(str[i], "android.hardware.Camera") || strstr(str[i], "LocationManager")) ev_media_hardware = str[i];
        
        if(strstr(str[i], "exec") || strstr(str[i], "loadLibrary") || strstr(str[i], "getDeviceId") || strstr(str[i], "sendTextMessage")) ev_exec_cmd = str[i];
    }

    // 3. Scan Classes
    for(uint32_t i = 0; i < class_count; i++){
        if(!class[i]) continue;
        if(strstr(class[i], "Http") || strstr(class[i], "Socket")) ev_http_socket = class[i];
        if(strstr(class[i], "Ljava/lang/reflect/Method;")) ev_reflection = class[i];
    }

    // 4. Scan Methods
    for(uint32_t i = 0; i < meth_class_count; i++){
        if(meth_class[i] && method[i]){
            if(strstr(meth_class[i], "Ljava/lang/Runtime;") && strstr(method[i], "exec")) evidence_runtime_exec = method[i];
            if(strstr(meth_class[i], "addJavascriptInterface")) evidence_js_interface = meth_class[i];
            if((strstr(meth_class[i], "Ljava/lang/System;") || strstr(meth_class[i], "Ljava/lang/Runtime;")) && 
               (strstr(method[i], "loadLibrary") || strstr(method[i], "load"))) evidence_dex_loader = method[i];
        }
    }

    // Logic Combinations
    if(ev_broadcast_receiver && ev_boot_completed) evidence_broadcast_boot = ev_boot_completed;
    if(ev_broadcast_receiver && ev_sms_send) evidence_sms_manager = ev_sms_send;
    if(ev_cipher && ev_file_io && ev_window_manager) evidence_crypto_file = ev_cipher;
    if(ev_log_util && ev_sensitive_string) evidence_log_secrets = ev_sensitive_string;
    if(ev_http_socket && ev_media_hardware) evidence_camera_mic_socket = ev_media_hardware;
    if(ev_reflection && ev_exec_cmd) evidence_reflection_exec = ev_exec_cmd;

    // Logging Findings
    if(evidence_accessibility) {
        add_finding(report, FINDING_DEX, rule_info_database[0].category, "CRITICAL", rule_info_database[0].description, "", filename, evidence_accessibility);
    }
    if(evidence_broadcast_boot) {
        add_finding(report, FINDING_DEX, rule_info_database[1].category, "CRITICAL", rule_info_database[1].description, "", filename, evidence_broadcast_boot);
    }
    if(evidence_notification_listener) {
        add_finding(report, FINDING_DEX, rule_info_database[2].category, "CRITICAL", rule_info_database[2].description, "", filename, evidence_notification_listener);
    }
    if(evidence_dex_loader) {
        add_finding(report, FINDING_DEX, rule_info_database[3].category, "CRITICAL", rule_info_database[3].description, "", filename, evidence_dex_loader);
    }
    if(evidence_crypto_file) {
        add_finding(report, FINDING_DEX, rule_info_database[4].category, "HIGH", rule_info_database[4].description, "", filename, evidence_crypto_file);
    }
    if(evidence_camera_mic_socket) {
        add_finding(report, FINDING_DEX, rule_info_database[5].category, "HIGH", rule_info_database[5].description, "", filename, evidence_camera_mic_socket);
    }
    if(evidence_reflection_exec) {
        add_finding(report, FINDING_DEX, rule_info_database[6].category, "HIGH", rule_info_database[6].description, "", filename, evidence_reflection_exec);
    }
    if(evidence_emulator_check) {
        add_finding(report, FINDING_DEX, rule_info_database[7].category, "HIGH", rule_info_database[7].description, "", filename, evidence_emulator_check);
    }
    if(evidence_runtime_exec) {
        add_finding(report, FINDING_DEX, rule_info_database[8].category, "HIGH", rule_info_database[8].description, "", filename, evidence_runtime_exec);
    }
    
    if(evidence_usage_stats) {
        add_finding(report, FINDING_DEX, rule_info_database[10].category, "MEDIUM", rule_info_database[10].description, "", filename, evidence_usage_stats);
    }
    if(evidence_clipboard) {
        add_finding(report, FINDING_DEX, rule_info_database[11].category, "MEDIUM", rule_info_database[11].description, "", filename, evidence_clipboard);
    }
    if(evidence_log_secrets) {
        add_finding(report, FINDING_DEX, rule_info_database[12].category, "MEDIUM", rule_info_database[12].description, "", filename, evidence_log_secrets);
    }
    if(evidence_js_interface) {
        add_finding(report, FINDING_DEX, rule_info_database[13].category, "MEDIUM", rule_info_database[13].description, "", filename, evidence_js_interface);
    }
    if(evidence_sms_manager) {
        add_finding(report, FINDING_DEX, rule_info_database[14].category, "MEDIUM", rule_info_database[14].description, "", filename, evidence_sms_manager);
    }
    if(evidence_root) {
        add_finding(report, FINDING_DEX, rule_info_database[15].category, "MEDIUM", rule_info_database[15].description, "", filename, evidence_root);
    }
}