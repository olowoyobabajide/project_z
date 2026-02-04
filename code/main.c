/*
 * Copyright (c) 2026 olowoyobabajide <olowoyobabajide@gmail.com>
 *
 * SPDX-License-Identifier: MIT
 */

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
        printf("Usage: ./fs-analyzer <path> [-d] [-o json <report_file.json>]\n");
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0){
            printf("Usage: ./fs-analyzer <path> [-d] [-o json <report_file.json>]\n\n");
            printf("Options:\n");
            printf("\t-d: Enable dex log\n");
            printf("\t-o json <report_file.json>: Output report in JSON format\n");
            printf("\t--help or -h: Show this help message\n");
            printf("\t--version or -v: Show version\n");
            return EXIT_SUCCESS;
        }
        else if(strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0){
            printf("Version: fs-analyzer 1.1.1\n");
            return EXIT_SUCCESS;
        } else if (strcmp(argv[i], "-o") == 0) {
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
             // Optional: Handle unknown flags or extra arguments
        }
    }

    if (!input_path) {
        printf("No input path provided.\n");
        return EXIT_FAILURE;
    }
     if (fnmatch("*.apk", basename(argv[1]), FNM_PATHNAME) != 0){
        printf("Input is not an apk file\n");
        return EXIT_FAILURE;
    }

    strncpy(buffer, input_path, PATH_MAX - 1);
    
    Report *report = NULL;
    if (json_output_file) {
        report = init_report();
    }

    printf("Input path: %s\n", buffer);

    printf("Analyzing Manifest...\n");
    filecheckManifest(buffer, report);
    
    init_elf_stats();
    
    printf("Analyzing Dex...\n");
    filecheckDex(buffer, enable_dex_log, report);
    
    printf("Analyzing functions...\n");
    filecheckso(buffer, report);
    
    printf("Reporting...\n");
    report_elf_stats(report);

    printf("Checking all files...\n");
    filecheckAll(buffer, report); 
    
    if (report && json_output_file) {
        save_report_json(report, json_output_file);
        printf("JSON report saved to %s\n", json_output_file);
        free_report(report);
    }
    
}