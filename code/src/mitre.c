/*
 * Copyright (c) 2026 olowoyobabajide <olowoyobabajide@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "mitre.h"

/* --- Code Execution --- */
const MitreTechnique MITRE_T1203 = {
    "T1203",
    "Exploitation for Client Execution",
    "Vulnerability exploitation may allow arbitrary code execution"
};

const MitreTechnique MITRE_T1059 = {
    "T1059",
    "Command and Scripting Interpreter",
    "Attacker may execute system commands"
};

const MitreTechnique MITRE_T1106 = {
    "T1106",
    "Native API",
    "Direct execution via native system APIs"
};

/* --- Privilege Escalation --- */
const MitreTechnique MITRE_T1068 = {
    "T1068",
    "Exploitation for Privilege Escalation",
    "Exploitation may allow elevation of privileges"
};

const MitreTechnique MITRE_T1548_001 = {
    "T1548.001",
    "Setuid and Setgid",
    "Abuse of SUID/SGID permissions for privilege escalation"
};

/* --- Process Injection --- */
const MitreTechnique MITRE_T1055 = {
    "T1055",
    "Process Injection",
    "Attacker may inject code into another process"
};

/* --- Credential Access --- */
const MitreTechnique MITRE_T1552_001 = {
    "T1552.001",
    "Credentials in Files",
    "Credentials stored insecurely in files"
};

const MitreTechnique MITRE_T1552_004 = {
    "T1552.004",
    "Private Keys",
    "Exposure of private or API keys"
};

/* --- Persistence --- */
const MitreTechnique MITRE_T1547 = {
    "T1547",
    "Boot or Logon Autostart Execution",
    "Persistence through startup mechanisms"
};

const MitreTechnique MITRE_T1053_003 = {
    "T1053.003",
    "Scheduled Task/Job: Cron",
    "Persistence via cron jobs"
};

/* --- Command & Control --- */
const MitreTechnique MITRE_T1071_001 = {
    "T1071.001",
    "Web Protocols",
    "Command and control over HTTP/HTTPS"
};

const MitreTechnique MITRE_T1573 = {
    "T1573",
    "Encrypted Channel",
    "Encrypted command and control channel"
};
