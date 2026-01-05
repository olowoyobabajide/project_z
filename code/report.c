#include "report.h"
#include <stdarg.h>

Report* init_report() {
    Report *r = (Report*)malloc(sizeof(Report));
    if (r) {
        r->head = NULL;
        r->tail = NULL;
        r->count = 0;
    }
    return r;
}

// Helper to duplicate strings safely
static char* safe_strdup(const char *s) {
    return s ? strdup(s) : strdup("");
}

void add_finding(Report *r, FindingType type, const char *name, const char *risk, const char *reason, const char *details, const char *source_file, const char *evidence) {
    if (!r) return;

    Finding *f = (Finding*)malloc(sizeof(Finding));
    f->type = type;
    f->name = safe_strdup(name);
    f->risk_level = safe_strdup(risk);
    f->reason = safe_strdup(reason);
    f->details = safe_strdup(details);
    f->source_file = safe_strdup(source_file);
    f->evidence = safe_strdup(evidence);
    f->next = NULL;

    if (r->tail) {
        r->tail->next = f;
        r->tail = f;
    } else {
        r->head = f;
        r->tail = f;
    }
    r->count++;
}

// Helper to escape JSON strings (handle quotes, newlines, etc.)
// Returns a dynamically allocated string that must be freed.
static char* json_escape(const char *str) {
    if (!str) return strdup("");
    
    // Worst case expansion is usually not massive for simple log text, 
    // but proper escaping is safer.
    size_t len = strlen(str);
    size_t cap = len * 2 + 1;
    char *out = (char*)malloc(cap);
    size_t j = 0;

    for (size_t i = 0; i < len; i++) {
        if (j + 4 >= cap) {
            cap *= 2;
            out = (char*)realloc(out, cap);
        }

        switch (str[i]) {
            case '"': out[j++] = '\\'; out[j++] = '"'; break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\b': out[j++] = '\\'; out[j++] = 'b'; break;
            case '\f': out[j++] = '\\'; out[j++] = 'f'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
            case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
            case '\t': out[j++] = '\\'; out[j++] = 't'; break;
            default:
                if ((unsigned char)str[i] < 32) {
                    j += sprintf(out + j, "\\u%04x", str[i]);
                } else {
                    out[j++] = str[i];
                }
        }
    }
    out[j] = '\0';
    return out;
}

static const char* type_to_string(FindingType t) {
    switch(t) {
        case FINDING_PERMISSION: return "Permission";
        case FINDING_ACTIVITY: return "Activity";
        case FINDING_SERVICE: return "Service";
        case FINDING_RECEIVER: return "Receiver";
        case FINDING_PROVIDER: return "Provider";
        case FINDING_DEX: return "DexAnalysis";
        case FINDING_ELF: return "ElfAnalysis";
        case FINDING_HASH: return "HashThreat";
        default: return "Unknown";
    }
}

void save_report_json(Report *r, const char *filename) {
    if (!r) return;

    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("Error opening report file");
        return;
    }

    fprintf(f, "{\n  \"findings\": [\n");

    Finding *current = r->head;
    while (current) {
        char *esc_name = json_escape(current->name);
        char *esc_risk = json_escape(current->risk_level);
        char *esc_reason = json_escape(current->reason);
        char *esc_details = json_escape(current->details);
        char *esc_source = json_escape(current->source_file);
        char *esc_evidence = json_escape(current->evidence);

        fprintf(f, "    {\n");
        fprintf(f, "      \"type\": \"%s\",\n", type_to_string(current->type));
        fprintf(f, "      \"name\": \"%s\",\n", esc_name);
        fprintf(f, "      \"risk_level\": \"%s\",\n", esc_risk);
        fprintf(f, "      \"reason\": \"%s\",\n", esc_reason);
        fprintf(f, "      \"source_file\": \"%s\",\n", esc_source);
        fprintf(f, "      \"evidence\": \"%s\",\n", esc_evidence);
        fprintf(f, "      \"details\": \"%s\"\n", esc_details);
        
        fprintf(f, "    }%s\n", current->next ? "," : "");

        free(esc_name);
        free(esc_risk);
        free(esc_reason);
        free(esc_details);
        free(esc_source);
        free(esc_evidence);

        current = current->next;
    }

    fprintf(f, "  ],\n");
    fprintf(f, "  \"total_findings\": %d\n", r->count);
    fprintf(f, "}\n");
    fclose(f);
}

void free_report(Report *r) {
    if (!r) return;
    Finding *current = r->head;
    while (current) {
        Finding *next = current->next;
        free(current->name);
        free(current->risk_level);
        free(current->reason);
        free(current->details);
        free(current->source_file);
        free(current->evidence);
        free(current);
        current = next;
    }
    free(r);
}
