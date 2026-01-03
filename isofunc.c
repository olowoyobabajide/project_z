#include "main.h"

void isoFunc(char *so_file);
int regex_scan(FILE*, char *);
int regex_command(FILE *log, char *buffer, char* section_name);
typedef struct unsafe{
char *unsafe_func;
} unsafeFunctions;
unsafeFunctions functions[] = {
    "strcpy","strcat","sprintf","vsprintf","gets","scanf","sscanf","memcpy","memmove","system","popen","execve","execv","execl","execvp","fork","posix","spawn","open","fopen","chmod","chown","ptrace","dlopen","dlsym","mmap","mprotect","socket","connect","bind","listen","accept","send","recv","gethostbyname","getaddrinfo","inet_addr","tmpnam","tmpfile"
};
const size_t NUM_UNSAFE_FUNCTION = sizeof(functions)/sizeof(unsafeFunctions);

/**
 * @struct command
 * @brief Holds the regex patterns to certain suspicious commands 
 */

typedef enum {
    COMMAND_INJECTION,
    FORMAT_STRING_WRITE,
    FORMAT_STRING_LEAK
} VulnerabilityType;

// Enum to rank the severity of a finding
typedef enum {
    CRITICAL,
    HIGH
} SeverityLevel;

/**
 * @struct VulnerabilityPattern
 * @brief Defines a complete vulnerability pattern for the scanner.
 */
typedef struct {
    const char*         vulnerability_name;  // Human-readable name of the finding
    VulnerabilityType   vulnerability_type;  // The class of vulnerability
    SeverityLevel       severity;            // The severity for prioritization
    const char*         regex_pattern;       // The (corrected) regex to find the pattern
    const char*         log_message_format;  // A printf-style format for logging
} VulnerabilityPattern;

/**
 * @brief An array of vulnerability patterns for detecting dangerous strings in binaries.
 *
 * NOTE: Regexes for commands have been simplified to find the command strings themselves,
 * which is what appears in a compiled binary's data sections.
 */
VulnerabilityPattern VULNERABILITY_PATTERNS[] = {
    // --- Command Injection Vulnerabilities ---
    {
        "Suspicious 'wget' Command", COMMAND_INJECTION, CRITICAL,
        "wget\\s+(-[a-zA-Z]+\\s+)*https?://",
        "[CRITICAL] Potential Command Injection Detected\n"
        "  - Reason:   A string containing the 'wget' command was found, likely for remote file download.\n"
        "  - Details:  If this string is passed to a function like system() or popen(), it could allow an attacker to execute arbitrary commands.\n"
        "  - Matched String: \"%%s\"\n"
        "  - Location: Section %%s at file offset 0x%%lX\n"
    },
    {
        "Suspicious 'curl' Command", COMMAND_INJECTION, CRITICAL,
        "curl\\s+(-[a-zA-Z]+\\s+)*https?://",
        "[CRITICAL] Potential Command Injection Detected\n"
        "  - Reason:   A string containing the 'curl' command was found, likely for remote data transfer.\n"
        "  - Details:  If this string is passed to a function like system() or popen(), it could allow an attacker to execute arbitrary commands.\n"
        "  - Matched String: \"%%s\"\n"
        "  - Location: Section %%s at file offset 0x%%lX\n"
    },
    {
        "Suspicious 'nc' or 'ncat' Command", COMMAND_INJECTION, CRITICAL,
        "(nc|ncat)\\s+.*-e\\s+/bin/sh", // Specifically look for reverse shells
        "[CRITICAL] Potential Command Injection Detected (Reverse Shell)\n"
        "  - Reason:   A string containing 'nc' or 'ncat' was found, configured to launch a shell (-e /bin/sh).\n"
        "  - Details:  This is a classic reverse shell payload. If executed, it would give an attacker full control over the device.\n"
        "  - Matched String: \"%%s\"\n"
        "  - Location: Section %%s at file offset 0x%%lX\n"
    },
    {
        "Suspicious 'rm' Command", COMMAND_INJECTION, CRITICAL,
        "rm\\s+(-[a-zA-Z]+\\s+)*\\s*(\\s/\\s|--no-preserve-root)", // Look for dangerous root deletion
        "[CRITICAL] Potential Command Injection Detected (Destructive)\n"
        "  - Reason:   A string containing a potentially destructive 'rm' command was found (e.g., deleting from root).\n"
        "  - Details:  Executing this command could delete critical files from the filesystem, rendering the application or device inoperable.\n"
        "  - Matched String: \"%%s\"\n"
        "  - Location: Section %%s at file offset 0x%%lX\n"
    },

    // --- Format String Vulnerabilities ---
    {
        "Format String Arbitrary Write", FORMAT_STRING_WRITE, CRITICAL,
        "%%.*n", // A simplified but effective regex to find any '%n' specifier
        "[CRITICAL] Potential Format String Arbitrary Write Vulnerability\n"
        "  - Reason:   The dangerous '%%n' format specifier was detected.\n"
        "  - Details:  This specifier can be used by an attacker to write data to arbitrary memory locations, potentially leading to code execution.\n"
        "  - Matched String: \"%%s\"\n"
        "  - Location: Section %%s at file offset 0x%%lX\n"
    },
    {
        "Format String Positional Access", FORMAT_STRING_LEAK, HIGH,
        "%%[0-9]+\\$", // Finds positional parameters like %2$x, %7$s, etc.
        "[HIGH] Potential Format String Memory Leak Vulnerability\n"
        "  - Reason:   Positional format specifiers (e.g., %%2$x) were detected.\n"
        "  - Details:  These specifiers allow an attacker to precisely read from specific memory locations on the stack, bypassing security measures like ASLR.\n"
        "  - Matched String: \"%%s\"\n"
        "  - Location: Section %%s at file offset 0x%lX\n"
    },
    {
        "Format String Memory Leak (High Density)", FORMAT_STRING_LEAK, HIGH,
        "(%%[pxs]){3,}", // Finds 3 or more instances of %p, %x, or %s in a row
        "[HIGH] Potential Format String Memory Leak Vulnerability\n"
        "  - Reason:   A high density of format specifiers was detected, likely for dumping stack memory.\n"
        "  - Details:  This pattern is often used in debugging but can be abused by an attacker to leak pointers, canaries, and other secrets from memory.\n"
        "  - Matched String: \"%%s\"\n"
        "  - Location: Section %%s at file offset 0x%%lX\n"
    }
};

// This calculates the number of patterns in the array for easy looping
const size_t NUM_VULN_PATTERNS = sizeof(VULNERABILITY_PATTERNS) / sizeof(VulnerabilityPattern);

/**
 * @struct SecretPattern
 * @brief Holds a name for a type of secret and the regex pattern to find it.
 */
typedef struct {
    const char* secret_type;
    const char* regex_pattern;
} SecretPattern;

/**
 * @brief An array of regular expression patterns for detecting hardcoded secrets.
 *
 * Each backslash from the original regex must be escaped with another backslash
 * for it to be a valid C string literal.
 */
SecretPattern SECRET_PATTERNS[] = {
    {"Cloudinary", "cloudinary://.*"},
    {"Firebase URL", ".*firebaseio\\.com"},
    {"Slack Token", "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"},
    {"RSA private key", "-----BEGIN RSA PRIVATE KEY-----"},
    {"SSH (DSA) private key", "-----BEGIN DSA PRIVATE KEY-----"},
    {"SSH (EC) private key", "-----BEGIN EC PRIVATE KEY-----"},
    {"PGP private key block", "-----BEGIN PGP PRIVATE KEY BLOCK-----"},
    {"Amazon AWS Access Key ID", "AKIA[0-9A-Z]{16}"},
    {"Amazon MWS Auth Token", "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"},
    {"AWS API Key", "AKIA[0-9A-Z]{16}"},
    {"Facebook Access Token", "EAACEdEose0cBA[0-9A-Za-z]+"},
    {"Facebook OAuth", "[fF][aA][cC][eE][bB][oO][oO][kK].*['\"][0-9a-f]{32}['\"]"},
    {"GitHub", "[gG][iI][tT][hH][uU][bB].*['\"][0-9a-zA-Z]{35,40}['\"]"},
    {"Generic API Key", "[aA][pP][iI][_]?[kK][eE][yY].*['\"][0-9a-zA-Z]{32,45}['\"]"},
    {"Generic Secret", "[sS][eE][cC][rR][eE][tT].*['\"][0-9a-zA-Z]{32,45}['\"]"},
    {"Google API Key", "AIza[0-9A-Za-z\\-_]{35}"},
    {"Google Cloud Platform API Key", "AIza[0-9A-Za-z\\-_]{35}"},
    {"Google Cloud Platform OAuth", "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"},
    {"Google Drive API Key", "AIza[0-9A-Za-z\\-_]{35}"},
    {"Google Drive OAuth", "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"},
    {"Google (GCP) Service-account", "\"type\": \"service_account\""},
    {"Google Gmail API Key", "AIza[0-9A-Za-z\\-_]{35}"},
    {"Google Gmail OAuth", "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"},
    {"Google OAuth Access Token", "ya29\\.[0-9A-Za-z\\-_]+"},
    {"Google YouTube API Key", "AIza[0-9A-Za-z\\-_]{35}"},
    {"Google YouTube OAuth", "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"},
    {"Heroku API Key", "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"},
    {"MailChimp API Key", "[0-9a-f]{32}-us[0-9]{1,2}"},
    {"Mailgun API Key", "key-[0-9a-zA-Z]{32}"},
    {"Password in URL", "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"},
    {"PayPal Braintree Access Token", "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"},
    {"Picatic API Key", "sk_live_[0-9a-z]{32}"},
    {"Slack Webhook", "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"},
    {"Stripe API Key", "sk_live_[0-9a-zA-Z]{24}"},
    {"Stripe Restricted API Key", "rk_live_[0-9a-zA-Z]{24}"},
    {"Square Access Token", "sq0atp-[0-9A-Za-z\\-_]{22}"},
    {"Square OAuth Secret", "sq0csp-[0-9A-Za-z\\-_]{43}"},
    {"Twilio API Key", "SK[0-9a-fA-F]{32}"},
    {"Twitter Access Token", "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}"},
    {"Twitter OAuth", "[tT][wW][iI][tT][tT][eE][rR].*['\"][0-9a-zA-Z]{35,44}['\"]"}
};

const size_t NUM_SECRET_PATTERNS = sizeof(SECRET_PATTERNS) / sizeof(SecretPattern);

// Counters for unsafe functions (Global)
static int global_unsafe_counts[sizeof(functions)/sizeof(unsafeFunctions)];

void init_elf_stats() {
    memset(global_unsafe_counts, 0, sizeof(global_unsafe_counts));
}

void report_elf_stats(Report *r) {
    for(int i = 0; i < NUM_UNSAFE_FUNCTION; i++){
        if(global_unsafe_counts[i] > 0){
            char details[256];
            snprintf(details, sizeof(details), "Count: %d", global_unsafe_counts[i]);
            // Source file is "All .so files" or we can list them if we tracked them, but user asked for simple aggregation.
            add_finding(r, FINDING_ELF, functions[i].unsafe_func, "HIGH", "Usage of unsafe function detected", details, "All scanned .so files", functions[i].unsafe_func);
        }
    }
}

void isoFunc(char *so_file){
    FILE *file, *log;
    // libhermestooling.so - 64, libcrsqlite.so - 64
    if((file = fopen(so_file, "rb")) == NULL){
        fprintf(stderr, "Unable to read *.so file\n");
        return;
    }
    if((log = fopen("LogSofile.txt", "a+")) == NULL){
        fprintf(stderr, "Unable to log *.so file\n");
        fclose(file);
        return;
    }

    // Counters for unsafe functions (Local to this file, we add to global later)
    // Actually, we can just add to global directly.
    
    unsigned char e_ident[EI_NIDENT];
    if (fread(e_ident, 1, EI_NIDENT, file) != EI_NIDENT) {
        fprintf(stderr, "Failed to read ELF identifier\n");
        fclose(file);
        return;
    }
    fseek(file, 0, SEEK_SET);

    /* 
       We will use Elf64 structures as the normalized form.
       If the file is 32-bit, we read into 32-bit structs and promote them to 64-bit.
    */
    Elf64_Ehdr ehdr;
    Elf64_Shdr *shdr = NULL;
    int is_32bit = (e_ident[EI_CLASS] == ELFCLASS32);

    if (is_32bit) {
        Elf32_Ehdr ehdr32;
        fread(&ehdr32, sizeof(Elf32_Ehdr), 1, file);
        
        // Normalize to Elf64
        ehdr.e_ident[EI_CLASS] = ELFCLASS32; // Keep original class info if needed or just use flag
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

        // Read Section Headers
        Elf32_Shdr *shdr32 = malloc(sizeof(Elf32_Shdr) * ehdr.e_shnum);
        if (!shdr32) { perror("malloc shdr32"); fclose(file); return; }
        
        fseek(file, ehdr.e_shoff, SEEK_SET);
        fread(shdr32, sizeof(Elf32_Shdr), ehdr.e_shnum, file);

        // Convert to Elf64_Shdr
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
        // 64-bit Logic
        fread(&ehdr, sizeof(Elf64_Ehdr), 1, file);
        shdr = malloc(sizeof(Elf64_Shdr) * ehdr.e_shnum);
        if (!shdr) { perror("malloc shdr"); fclose(file); return; }
        
        fseek(file, ehdr.e_shoff, SEEK_SET);
        fread(shdr, sizeof(Elf64_Shdr), ehdr.e_shnum, file);
    }

    if (ehdr.e_type != ET_DYN) {
        printf("Not a dynamic shared object (ET_DYN)\n");
    }

    printf("Analyzed ELF: %s-bit, Sections: %d\n", is_32bit ? "32" : "64", ehdr.e_shnum);

    // --- Unified Analysis Loop ---
    
    // Load Section Header String Table
    char *shstrtab = NULL;
    if (ehdr.e_shstrndx != SHN_UNDEF && ehdr.e_shstrndx < ehdr.e_shnum) {
         shstrtab = malloc(shdr[ehdr.e_shstrndx].sh_size);
         if (shstrtab) {
            fseek(file, shdr[ehdr.e_shstrndx].sh_offset, SEEK_SET);
            fread(shstrtab, shdr[ehdr.e_shstrndx].sh_size, 1, file);
         }
    }
    
    // Pointers for symbol string tables
    char *dynsym_strtab = NULL;
    char *symtab_strtab = NULL;

    // First pass: locate string tables
     for(int i = 0; i < ehdr.e_shnum; i++){
        if (!shstrtab) break;
        char *section_name = shstrtab + shdr[i].sh_name;
        
        if(shdr[i].sh_type == SHT_STRTAB) {
            if(strcmp(section_name, ".dynstr") == 0){
                dynsym_strtab = malloc(shdr[i].sh_size);
                if(dynsym_strtab) {
                    fseek(file, shdr[i].sh_offset, SEEK_SET);
                    fread(dynsym_strtab, 1, shdr[i].sh_size, file);
                }
            }
            if(strcmp(section_name, ".strtab") == 0){
                symtab_strtab = malloc(shdr[i].sh_size);
                if(symtab_strtab) {
                    fseek(file, shdr[i].sh_offset, SEEK_SET);
                    fread(symtab_strtab, 1, shdr[i].sh_size, file);
                }
            }
        }
    }

    // Second pass: Process sections
    for(int i = 0; i < ehdr.e_shnum; i++){
        if (!shstrtab) continue;
        char *section_name = shstrtab + shdr[i].sh_name;
        
        // 1. Content Scanning (Regex)
        // Only scan sections that occupy space in file and are of interest
        if(shdr[i].sh_type == SHT_PROGBITS || 
           (shdr[i].sh_type == SHT_STRTAB && (strcmp(section_name, ".dynstr") == 0 || strcmp(section_name, ".strtab") == 0))) 
        {
            if (shdr[i].sh_size > 0 && shdr[i].sh_size < 100 * 1024 * 1024) { // Limit size scan to 100MB avoid DoS
                char *content = malloc(shdr[i].sh_size + 1); // +1 for safety null term if treated as string
                if (content) {
                    fseek(file, shdr[i].sh_offset, SEEK_SET);
                    fread(content, 1, shdr[i].sh_size, file);
                    content[shdr[i].sh_size] = '\0';

                    if(strcmp(section_name, ".rodata") == 0 || strcmp(section_name, ".data") == 0 ||
                       strcmp(section_name, ".dynstr") == 0 || strcmp(section_name, ".strtab") == 0)
                    {
                         regex_scan(log, content);
                         regex_command(log, content, section_name);
                    }
                    free(content);
                }
            }
        }

        // 2. Symbol Table Analysis
        if(shdr[i].sh_type == SHT_DYNSYM || shdr[i].sh_type == SHT_SYMTAB){
            char *name_source = (shdr[i].sh_type == SHT_DYNSYM) ? dynsym_strtab : symtab_strtab;
            if (!name_source) continue;

            // We must handle 32 vs 64 bit entries here
            uint32_t entry_size = shdr[i].sh_entsize;
            if (entry_size == 0) continue; 
            uint32_t sym_count = shdr[i].sh_size / entry_size;

            fseek(file, shdr[i].sh_offset, SEEK_SET);
            
            // Allocate a buffer for one entry (max size is Elf64_Sym)
            // Or allocate entire table. Let's do entry-by-entry to avoid large allocations or 
            // separate arrays. Actually, reading whole block is faster IO.
            
            void *sym_data = malloc(shdr[i].sh_size);
            if(sym_data) {
                fread(sym_data, shdr[i].sh_size, 1, file);

                for(int j = 0; j < sym_count; j++){
                    char *sym_name = NULL;
                    unsigned char type = 0;
                    uint16_t shndx = 0;

                    if (is_32bit) {
                         Elf32_Sym *sym32 = (Elf32_Sym *)((char*)sym_data + j * sizeof(Elf32_Sym));
                         type = ELF32_ST_TYPE(sym32->st_info);
                         shndx = sym32->st_shndx;
                         sym_name = name_source + sym32->st_name;
                    } else {
                         Elf64_Sym *sym64 = (Elf64_Sym *)((char*)sym_data + j * sizeof(Elf64_Sym));
                         type = ELF64_ST_TYPE(sym64->st_info);
                         shndx = sym64->st_shndx;
                         sym_name = name_source + sym64->st_name;
                    }

                    if(type == STT_FUNC && shndx == SHN_UNDEF){
                         for(int count = 0; count < NUM_UNSAFE_FUNCTION; count++){
                                if(strcmp(sym_name, functions[count].unsafe_func) == 0){
                                    global_unsafe_counts[count]++;
                                    fprintf(log, "INFO: FOUND IMPORTED FUNCTION. Checking against rules...\n");
                                    fprintf(log, "\tVULNERABILITY DETECTED: Use of insecure imported function: %s\n", sym_name);
                                }
                         }
                    }
                }
                free(sym_data);
            }
        }
    }

    if (shdr) free(shdr);
    if (shstrtab) free(shstrtab);
    if (dynsym_strtab) free(dynsym_strtab);
    if (symtab_strtab) free(symtab_strtab);
    fclose(file);
    fclose(log);
}
int regex_scan(FILE *log, char *buffer){
    for(int i = 0; i < NUM_SECRET_PATTERNS; i++){
        regex_t reg_x;
        int reg;

        reg = regcomp(&reg_x, SECRET_PATTERNS[i].regex_pattern, REG_EXTENDED);

        reg = regexec(&reg_x, buffer, 0, NULL, 0);

        if(reg == 0){
            fprintf(log, "VULNERABILITY FOUND! Hardcoded string %s detected in binary\n", SECRET_PATTERNS[i].secret_type);
        }
        regfree(&reg_x);
    }  
}

int regex_command(FILE *log, char *buffer, char* section_name){
    for(int i = 0; i < NUM_VULN_PATTERNS; i++){

        regex_t reg_x;

        int reg;
        reg = regcomp(&reg_x, VULNERABILITY_PATTERNS[i].regex_pattern, REG_EXTENDED);

        reg = regexec(&reg_x, buffer, 0, NULL, 0);
        if(reg == 0){
            fprintf(log, "%ssectionname: %s\n", VULNERABILITY_PATTERNS[i].log_message_format, section_name);
        }
        regfree(&reg_x);
    }
}
