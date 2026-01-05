#include "main.h"

char buffer[PATH_MAX];

int main(int argc, char **argv)
{
    char *json_output_file = NULL;
    char *input_path = NULL;

    if(argc < 2)
    {
        printf("Insufficient input\n");
        printf("Usage: ./fs_analyzer <path> [-o json <report_file.json>]\n");
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 2 < argc) {
                if (strcmp(argv[i+1], "json") == 0) {
                    json_output_file = argv[i+2];
                    i += 2; // Skip format and filename
                } else {
                    fprintf(stderr, "Error: Unsupported output format '%s'. Only 'json' is supported.\n", argv[i+1]);
                    return EXIT_FAILURE;
                }
            } else {
                fprintf(stderr, "Usage: -o json <filename>\n");
                return EXIT_FAILURE;
            }
        } else if (input_path == NULL) {
            input_path = argv[i];
        } else {
            // potential other args or multiple paths
        }
    }

    if (!input_path) {
        printf("No input path provided.\n");
        return EXIT_FAILURE;
    }

    strncpy(buffer, input_path, PATH_MAX - 1);
    
    Report *report = NULL;
    if (json_output_file) {
        report = init_report();
    }

    // Clear old log file
    // Clear old log files
    remove("manifestLog.txt");
    remove("dex_analysis.txt");

    printf("Calling apk_check with path: %s\n", buffer);
    apk_check(buffer);

    char buf_path[PATH_MAX];
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '/') {
        snprintf(buf_path, sizeof(buf_path), "%stemp", buffer);
    } else {
        snprintf(buf_path, sizeof(buf_path), "%s/temp", buffer);
    }

    printf("Calling filecheckManifest with path: %s\n", buf_path);
    filecheckManifest(buf_path, report); // For Android Manifest
    init_elf_stats();
    
    printf("Calling filecheckDex with path: %s\n", buf_path);
    filecheckDex(buf_path, report); // For .dex files 
    printf("Calling filecheckso with path: %s\n", buf_path);
    filecheckso(buf_path); // Report passed via global finalizer
    
    report_elf_stats(report);

    printf("Calling filecheckAll with path: %s\n", buf_path); // Dynamic temp path
    
    filecheckAll(buf_path); // for checking all files
    
    if (report && json_output_file) {
        save_report_json(report, json_output_file);
        printf("JSON report saved to %s\n", json_output_file);
        free_report(report);
    }
    
    execve("delete.sh", NULL, NULL);

}