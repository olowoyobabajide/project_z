/*
 * Copyright (c) 2026 olowoyobabajide <olowoyobabajide@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef MITRE_H
#define MITRE_H

typedef struct {
    const char *technique_id;     // e.g. "T1203"
    const char *name;             // Human-readable name
    const char *reason;           // Why this technique applies
} MitreTechnique;

/* --- Code Execution --- */
extern const MitreTechnique MITRE_T1203;
extern const MitreTechnique MITRE_T1059;
extern const MitreTechnique MITRE_T1106;

/* --- Privilege Escalation --- */
extern const MitreTechnique MITRE_T1068;
extern const MitreTechnique MITRE_T1548_001;

/* --- Process Injection --- */
extern const MitreTechnique MITRE_T1055;

/* --- Credential Access --- */
extern const MitreTechnique MITRE_T1552_001;
extern const MitreTechnique MITRE_T1552_004;

/* --- Persistence --- */
extern const MitreTechnique MITRE_T1547;
extern const MitreTechnique MITRE_T1053_003;

/* --- Command & Control --- */
extern const MitreTechnique MITRE_T1071_001;
extern const MitreTechnique MITRE_T1573;

#endif // MITRE_H
