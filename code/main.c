#include "main.h"

char buffer[PATH_MAX];

int main(int argc, char **argv)
{
    char *json_output_file = NULL;
    char *input_path = NULL;
    int enable_dex_log = 0;

    if(argc < 2)
    {
        printf("Insufficient input\n");
        printf("Usage: ./fs_analyzer <path> [-d] [-o json <report_file.json>]\n");
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
        } else if (strcmp(argv[i], "-d") == 0) {
            enable_dex_log = 1;
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

    // Clear old log files
    remove("manifestLog.txt");
    remove("dex_analysis.txt");

    printf("Input path: %s\n", buffer);

    filecheckManifest(buffer, report); // For Android Manifest
    init_elf_stats();
    
    filecheckDex(buffer, enable_dex_log, report); // For .dex files 
    filecheckso(buffer, report); // Report passed via global finalizer
    
    report_elf_stats(report);

    filecheckAll(buffer, report); // for checking all files
    
    if (report && json_output_file) {
        save_report_json(report, json_output_file);
        printf("JSON report saved to %s\n", json_output_file);
        free_report(report);
    }
    

}