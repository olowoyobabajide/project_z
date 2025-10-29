#include "main.h"

void isoFunc(char *iso_file);
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

void isoFunc(char *so_file){
    FILE *file, *log;
    // libhermestooling.so - 64, libcrsqlite.so - 64
    if((file = fopen(so_file, "rb")) == NULL){
        fprintf(stderr, "Unable to read *.so file\n");
        fclose(file);
        return;
    }
    if((log = fopen("LogSofile.txt", "w")) == NULL){
        fprintf(stderr, "Unable to log *.so file\n");
        fclose(file);
        return;
    }
    Elf32_Ehdr ehdr32;
    Elf64_Ehdr ehdr64;
    Elf32_Shdr *shdr32;
    Elf64_Shdr *shdr64;
    //fseek(file, 0x0, SEEK_SET);
    unsigned char e_ident[EI_NIDENT];
    fread(&e_ident, 1, EI_NIDENT, file);
    fseek(file, 0, SEEK_SET);
    if(e_ident[EI_CLASS] == 1){
        fread(&ehdr32, sizeof(Elf32_Ehdr), 1, file);
        if (ehdr32.e_type == ET_DYN){
            printf("%d\n", ehdr32.e_type);
            printf("Valid *.so file\n");
        }
        else if(ehdr32.e_type != ET_DYN){
            printf("Invalid *.so file\n");
        }
        printf("Section header: %u\n", ehdr32.e_shoff);
        fseek(file, ehdr32.e_shoff, SEEK_SET);
        //fread(&shdr32, sizeof(Elf32_Shdr), 1, file);
        //printf("%u\n", shdr32[].sh_type);

    }
    else{
        fread(&ehdr64, sizeof(Elf64_Ehdr), 1, file);
        shdr64 = malloc(sizeof(Elf64_Shdr) * ehdr64.e_shnum);
        if (ehdr64.e_type == ET_DYN){
            printf("Valid shared object file\n");
        }
        else{
            printf("Invalid *.so file\n");
        }
        printf("Check iso file %d\n", ehdr64.e_type);
        printf("Section header: %u\n", ehdr64.e_shoff);
        printf("Number of section headers: %u\n", ehdr64.e_shnum);
        
        fseek(file, ehdr64.e_shoff, SEEK_SET);
        for(int i = 0; i < ehdr64.e_shnum; i++){
            fread(&shdr64[i], sizeof(Elf64_Shdr), 1, file);
            printf("Section header: %d type: %d\n", i, shdr64[i].sh_type);
    
        }
    
        char *shstrtab, *dynsym_strtab, *symtab_strtab, *section_name;
        shstrtab = malloc(shdr64[ehdr64.e_shstrndx].sh_size);
        fseek(file, shdr64[ehdr64.e_shstrndx].sh_offset, SEEK_SET);
        fread(shstrtab, shdr64[ehdr64.e_shstrndx].sh_size, 1, file);

        for(int i = 0; i < ehdr64.e_shnum; i++){
            if(shdr64[i].sh_type == SHT_STRTAB){
                section_name = shstrtab+shdr64[i].sh_name;
                if(strcmp(section_name, ".dynstr") == 0){
                    dynsym_strtab = malloc(shdr64[i].sh_size);
                    if(!dynsym_strtab){perror("Failed to allocate memory for dynamic string table\n");}
                    fseek(file, shdr64[i].sh_offset, SEEK_SET);
                    if (fread(dynsym_strtab, 1, shdr64[i].sh_size, file) != shdr64[i].sh_size) {
                    fprintf(stderr, "failed to read .dynstr\n"); return;
                    }
                }
                if(strcmp(section_name, ".strtab") == 0){
                    symtab_strtab = malloc(shdr64[i].sh_size);
                    fseek(file, shdr64[i].sh_offset, SEEK_SET);
                    fread(symtab_strtab, 1, shdr64[i].sh_size,file);
                }
            }
        }
        for(int i = 0; i < ehdr64.e_shnum; i++){
            section_name = shstrtab+shdr64[i].sh_name;
            char *section_content;
            section_content = malloc(shdr64[i].sh_size);
            fseek(file, shdr64[i].sh_offset, SEEK_SET);
            fread(section_content, shdr64[i].sh_size, 1, file);
            if(shdr64[i].sh_type == SHT_PROGBITS){
                printf("Index: %d %s\n", i, section_name);
                printf("%s\n", section_content);

                if(strcmp(section_name, ".rodata") == 0 || strcmp(section_name, ".data") == 0){
                    regex_scan(log, section_content);
                    regex_command(log, section_content, section_name);
                }
            }
            if(shdr64[i].sh_type == SHT_STRTAB){
                if(strcmp(section_name, ".dynstr") == 0 || strcmp(section_name, ".strtab") == 0){
                    printf("Index: %d %s\n", i, section_name);
                               
                    regex_scan(log, dynsym_strtab);
                    regex_command(log, dynsym_strtab, section_name);
                }
            }
            if(shdr64[i].sh_type == SHT_DYNSYM || shdr64[i].sh_type == SHT_SYMTAB){
                char *name_source = (shdr64[i].sh_type == SHT_DYNSYM) ? dynsym_strtab : symtab_strtab;
                Elf64_Sym *elf64_sym = malloc(shdr64[i].sh_size);
                
                if(strcmp(section_name, ".dynsym") == 0 || strcmp(section_name, ".symtab") == 0){
                    uint32_t sym_tables = shdr64[i].sh_size/shdr64[i].sh_entsize;
                
                    fseek(file, shdr64[i].sh_offset, SEEK_SET);
                    fread(elf64_sym, shdr64[i].sh_size, 1, file);
                    
                    for(int j = 0; j < sym_tables; j++){
                        if(ELF32_ST_TYPE(elf64_sym[j].st_info) == STT_FUNC && elf64_sym[j].st_shndx == SHN_UNDEF){
                        
                            char *sym_name = name_source+elf64_sym[j].st_name;
                            printf("INFO: FOUND IMPORTED FUNCTION. Checking against rules...\n");
                            for(int count = 0; count < NUM_UNSAFE_FUNCTION; count++){
                                if(strcmp(sym_name, functions[count].unsafe_func) == 0){
                                    fprintf(log, "INFO: FOUND IMPORTED FUNCTION. Checking against rules...\n");
                                    fprintf(log, "\tVULNERABILITY DETECTED: Use of insecure imported function: %s\n", sym_name);
                                }
                                /*else{
                                    fprintf(log, "INFO: Imported function %s is not on the high-risk list.\n", sym_name);
                                }*/
                            }
    
                        }
                    }

                }   
            }
        }

    } 

    fclose(file);
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
