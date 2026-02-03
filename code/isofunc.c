/*
 * Copyright (c) 2026 olowoyobabajide <olowoyobabajide@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "main.h"

void isoFunc(char *so_buf, size_t so_size, const char *filename, Report *r);
int regex_scan(char *buffer, const char *filename, Report *r);
int regex_command(char *buffer, char* section_name, const char *filename, Report *r);
typedef struct unsafe{
char *unsafe_func;
} unsafeFunctions;

unsafeFunctions list[] = {
    {"strcpy"}, {"strcat"}, {"gets"}, {"sprintf"}, {"vsprintf"}, {"scanf"}, {"fscanf"},
    {"sscanf"}, {"vscanf"}, {"vfscanf"}, {"vsscanf"}, {"realpath"}, {"getsw"}, {"getc"},
    {"getchar"}, {"fgetc"}, {"getw"}, {"read"}, {"pread"}
};

size_t NUM_UNSAFE_FUNCTIONS = sizeof(list) / sizeof(unsafeFunctions);

typedef struct {
    const char *regex_pattern;
    const char *secret_type;
} SecretPattern;

SecretPattern SECRET_PATTERNS[] = {
    {"AIza[0-9A-Za-z_-]{35}", "Google API Key"},
    {"access_token\\$([0-9a-f]{32})", "Facebook Access Token"},
    {"sq0atp-[0-9A-Za-z_-]{22}", "Square Personal Access Token"},
    {"sq0csp-[0-9A-Za-z_-]{43}", "Square OAuth Secret"},
    {"SK[0-9a-fA-F]{32}", "Twilio API Key"},
    {"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", "Slack Webhook"},
    {"[a-zA-Z0-9_-]{20,}", "Generic High-Entropy String"}
};

size_t NUM_SECRET_PATTERNS = sizeof(SECRET_PATTERNS) / sizeof(SecretPattern);

typedef enum {
    CRITICAL,
    HIGH
} Severity;

typedef struct {
    const char *regex_pattern;
    const char *vulnerability_name;
    const char *log_message_format;
    Severity severity;
} VulnerabilityPattern;

VulnerabilityPattern VULNERABILITY_PATTERNS[] = {
    {"system[[:space:]]*\\(", "Arbitrary Command Execution", "CRITICAL! system() call detected in ", CRITICAL},
    {"exec[lpevp]*[[:space:]]*\\(", "Process Execution", "HIGH! exec() family call detected in ", HIGH},
    {"popen[[:space:]]*\\(", "Pipe Open", "HIGH! popen() call detected in ", HIGH},
    {"/bin/sh", "Shell Path Reference", "HIGH! Shell path (/bin/sh) reference in ", HIGH}
};

size_t NUM_VULN_PATTERNS = sizeof(VULNERABILITY_PATTERNS) / sizeof(VulnerabilityPattern);

uint32_t unsafe_calls_count = 0;

void init_elf_stats() {
    unsafe_calls_count = 0;
}

void report_elf_stats(Report *r) {
    if (unsafe_calls_count > 0) {
        char details[64];
        snprintf(details, sizeof(details), "Found %u potential unsafe signal/IO calls", unsafe_calls_count);
        const MitreTechnique *mitre_list[] = { &MITRE_T1203 };
        add_finding(r, FINDING_ELF, "Legacy Unsafe Functions", "LOW", "The binary contains calls to functions that are often associated with security vulnerabilities (e.g., strcpy, sprintf).", details, "Multiple SO files", "", mitre_list, 1);
    }
}

void isoFunc(char *so_buf, size_t so_size, const char *filename, Report *r){
    FILE *file;
    
    if((file = fmemopen(so_buf, so_size, "rb")) == NULL){
        fprintf(stderr, "Unable to open memory stream for *.so file\n");
        return;
    }

    unsigned char e_ident[EI_NIDENT];
    if (fread(e_ident, 1, EI_NIDENT, file) != EI_NIDENT) {
        fprintf(stderr, "Failed to read ELF identifier\n");
        fclose(file);
        return;
    }
    fseek(file, 0, SEEK_SET);

    Elf64_Ehdr ehdr;
    Elf64_Shdr *shdr = NULL;
    int is_32bit = (e_ident[EI_CLASS] == ELFCLASS32);

    if (is_32bit) {
        Elf32_Ehdr ehdr32;
        fread(&ehdr32, sizeof(Elf32_Ehdr), 1, file);
        
        ehdr.e_ident[EI_CLASS] = ELFCLASS32;
        ehdr.e_type = ehdr32.e_type;
        ehdr.e_machine = ehdr32.e_machine;
        ehdr.e_version = ehdr32.e_version;
        ehdr.e_entry = ehdr32.e_entry;
        ehdr.e_phoff = ehdr32.e_phoff;
        ehdr.e_shoff = ehdr32.e_shoff;
        ehdr.e_flags = ehdr32.e_flags;
        ehdr.e_ehsize = ehdr32.e_ehsize;
        ehdr.e_phentsize = ehdr32.e_phentsize;
        ehdr.e_phnum = ehdr32.e_phnum;
        ehdr.e_shentsize = ehdr32.e_shentsize;
        ehdr.e_shnum = ehdr32.e_shnum;
        ehdr.e_shstrndx = ehdr32.e_shstrndx;

        Elf32_Shdr *shdr32 = malloc(sizeof(Elf32_Shdr) * ehdr.e_shnum);
        if (!shdr32) { perror("malloc shdr32"); fclose(file); return; }
        
        fseek(file, ehdr.e_shoff, SEEK_SET);
        fread(shdr32, sizeof(Elf32_Shdr), ehdr.e_shnum, file);

        shdr = malloc(sizeof(Elf64_Shdr) * ehdr.e_shnum);
        if (!shdr) { perror("malloc shdr"); free(shdr32); fclose(file); return; }

        for (int i = 0; i < ehdr.e_shnum; i++) {
            shdr[i].sh_name = shdr32[i].sh_name;
            shdr[i].sh_type = shdr32[i].sh_type;
            shdr[i].sh_flags = shdr32[i].sh_flags;
            shdr[i].sh_addr = shdr32[i].sh_addr;
            shdr[i].sh_offset = shdr32[i].sh_offset;
            shdr[i].sh_size = shdr32[i].sh_size;
            shdr[i].sh_link = shdr32[i].sh_link;
            shdr[i].sh_info = shdr32[i].sh_info;
            shdr[i].sh_addralign = shdr32[i].sh_addralign;
            shdr[i].sh_entsize = shdr32[i].sh_entsize;
        }
        free(shdr32);

    } else {
        fread(&ehdr, sizeof(Elf64_Ehdr), 1, file);
        shdr = malloc(sizeof(Elf64_Shdr) * ehdr.e_shnum);
        if (!shdr) { perror("malloc shdr"); fclose(file); return; }
        
        fseek(file, ehdr.e_shoff, SEEK_SET);
        fread(shdr, sizeof(Elf64_Shdr), ehdr.e_shnum, file);
    }

    if (ehdr.e_type != ET_DYN) {
        free(shdr);
        fclose(file);
        return;
    }

    char *shstrtab = NULL;
    if (ehdr.e_shstrndx != SHN_UNDEF && ehdr.e_shstrndx < ehdr.e_shnum) {
         shstrtab = malloc(shdr[ehdr.e_shstrndx].sh_size);
         if (shstrtab) {
            fseek(file, shdr[ehdr.e_shstrndx].sh_offset, SEEK_SET);
            fread(shstrtab, shdr[ehdr.e_shstrndx].sh_size, 1, file);
         }
    }

    for (int i = 0; i < ehdr.e_shnum; i++) {
        char *section_name = "";
        if (shstrtab && shdr[i].sh_name < shdr[ehdr.e_shstrndx].sh_size) {
            section_name = shstrtab + shdr[i].sh_name;
        }

        if (shdr[i].sh_type == SHT_DYNSYM || shdr[i].sh_type == SHT_SYMTAB) {
            int num_symbols = shdr[i].sh_size / shdr[i].sh_entsize;
            char *strtab = NULL;
            if (shdr[i].sh_link < ehdr.e_shnum) {
                strtab = malloc(shdr[shdr[i].sh_link].sh_size);
                if (strtab) {
                    long current_pos = ftell(file);
                    fseek(file, shdr[shdr[i].sh_link].sh_offset, SEEK_SET);
                    fread(strtab, shdr[shdr[i].sh_link].sh_size, 1, file);
                    fseek(file, current_pos, SEEK_SET);
                }
            }

            if (strtab) {
                if (is_32bit) {
                    Elf32_Sym *syms32 = malloc(shdr[i].sh_size);
                    fseek(file, shdr[i].sh_offset, SEEK_SET);
                    fread(syms32, shdr[i].sh_size, 1, file);
                    for (int j = 0; j < num_symbols; j++) {
                        char *sym_name = strtab + syms32[j].st_name;
                        for (int k = 0; k < NUM_UNSAFE_FUNCTIONS; k++) {
                            if (strcmp(sym_name, list[k].unsafe_func) == 0) {
                                unsafe_calls_count++;
                            }
                        }
                    }
                    free(syms32);
                } else {
                    Elf64_Sym *syms64 = malloc(shdr[i].sh_size);
                    fseek(file, shdr[i].sh_offset, SEEK_SET);
                    fread(syms64, shdr[i].sh_size, 1, file);
                    for (int j = 0; j < num_symbols; j++) {
                        char *sym_name = strtab + syms64[j].st_name;
                        for (int k = 0; k < NUM_UNSAFE_FUNCTIONS; k++) {
                            if (strcmp(sym_name, list[k].unsafe_func) == 0) {
                                unsafe_calls_count++;
                            }
                        }
                    }
                    free(syms64);
                }
                free(strtab);
            }
        }

        if (shdr[i].sh_type == SHT_PROGBITS || shdr[i].sh_type == SHT_STRTAB) {
            if (shdr[i].sh_size > 0 && shdr[i].sh_size < 10 * 1024 * 1024) {
                char *content = malloc(shdr[i].sh_size + 1);
                if (content) {
                    fseek(file, shdr[i].sh_offset, SEEK_SET);
                    fread(content, shdr[i].sh_size, 1, file);
                    content[shdr[i].sh_size] = '\0';

                    if(strcmp(section_name, ".rodata") == 0 || strcmp(section_name, ".data") == 0 ||
                       strcmp(section_name, ".dynstr") == 0 || strcmp(section_name, ".strtab") == 0)
                    {
                         regex_scan(content, filename, r);
                         regex_command(content, section_name, filename, r);
                    }
                    free(content);
                }
            }
        }
    }

    if (shstrtab) free(shstrtab);
    if (shdr) free(shdr);
    fclose(file);
}

int regex_scan(char *buffer, const char *filename, Report *r){
    for(int i = 0; i < NUM_SECRET_PATTERNS; i++){
        regex_t reg_x;
        int reg;
        if (regcomp(&reg_x, SECRET_PATTERNS[i].regex_pattern, REG_EXTENDED) != 0) {
            continue;
        }
        reg = regexec(&reg_x, buffer, 0, NULL, 0);
        if(reg == 0){
            add_finding(r, FINDING_ELF, SECRET_PATTERNS[i].secret_type, "HIGH", "Hardcoded secret detected in shared object", "", filename, SECRET_PATTERNS[i].regex_pattern, NULL, 0);
        }
        regfree(&reg_x);
    }  
    return 0;
}

int regex_command(char *buffer, char* section_name, const char *filename, Report *r){
    for(int i = 0; i < NUM_VULN_PATTERNS; i++){
        regex_t reg_x;
        int reg;
        if (regcomp(&reg_x, VULNERABILITY_PATTERNS[i].regex_pattern, REG_EXTENDED) != 0) {
            continue;
        }
        reg = regexec(&reg_x, buffer, 0, NULL, 0);
        if(reg == 0){
            char risk[16];
            snprintf(risk, sizeof(risk), "%s", VULNERABILITY_PATTERNS[i].severity == CRITICAL ? "CRITICAL" : "HIGH");
            add_finding(r, FINDING_ELF, VULNERABILITY_PATTERNS[i].vulnerability_name, risk, "Potentially dangerous command string detected", section_name, filename, VULNERABILITY_PATTERNS[i].regex_pattern, NULL, 0);
        }
        regfree(&reg_x);
    }
    return 0;
}
