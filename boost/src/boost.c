/**
 * @file boost.c
 * @brief Boost Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

#include "boost.h"
#define TDX_EXTEND_RTMR_DATA_LEN 48

#ifdef HAVE_TDX_ATTEST
#include <tdx_attest.h>
#else
// Mock implementation for non-TDX environments
#define TDX_REPORT_DATA_SIZE 64
#define TDX_ATTEST_SUCCESS 0
#define TDX_ATTEST_ERROR_INVALID_PARAMETER -1
#define TDX_UUID_SIZE 16

typedef struct _tdx_uuid_t
{
    uint8_t d[TDX_UUID_SIZE];
} tdx_uuid_t;

typedef struct
{
    uint8_t d[TDX_REPORT_DATA_SIZE];
} tdx_report_data_t;

typedef struct
{
    uint8_t d[1024];
} tdx_report_t;

typedef struct
{
    uint32_t version;
    uint32_t rtmr_index;
    uint8_t extend_data[TDX_EXTEND_RTMR_DATA_LEN];
    uint32_t event_data_size;
} tdx_rtmr_event_t;


int tdx_att_get_report(const tdx_report_data_t *report_data, tdx_report_t *report)
{
    // Mock implementation for testing
    const uint8_t mock_report_data[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xA5, 0xB7, 0xC9, 0xD1, 0xE3, 0xF5, 0x17, 0x29,
        0x3B, 0x4D, 0x5F, 0x71, 0x83, 0x95, 0xA7, 0xB9};

    memset(report->d, 0, sizeof(report->d));
    memcpy(report->d, mock_report_data, sizeof(mock_report_data));

    if (report_data)
    {
        for (int i = 0; i < TDX_REPORT_DATA_SIZE && i + 32 < sizeof(report->d); i++)
        {
            report->d[32 + i] ^= report_data->d[i];
        }
    }

    for (int i = 32 + TDX_REPORT_DATA_SIZE; i < sizeof(report->d); i++)
    {
        report->d[i] = (i * 0x53) & 0xFF;
    }

    printf("[MOCK] Generated TDX report\n");
    return TDX_ATTEST_SUCCESS;
}

int tdx_att_extend(const tdx_rtmr_event_t *p_rtmr_event)
{
    // Mock implementation for testing
    if (!p_rtmr_event || p_rtmr_event->version != 1 || p_rtmr_event->rtmr_index > 3)
    {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    printf("[MOCK] Extended RTMR[%d] with data\n", p_rtmr_event->rtmr_index);
    return TDX_ATTEST_SUCCESS;
}

// Mock implementation for tdx_att_get_quote
int tdx_att_get_quote(const tdx_report_data_t *report_data,
                      void *p_qe_target_info, uint32_t qe_target_info_size,
                      tdx_uuid_t *p_att_key_id,
                      uint8_t **pp_quote, uint32_t *p_quote_size,
                      uint32_t flags)
{
    tdx_report_t report;
    if (tdx_att_get_report(report_data, &report) != TDX_ATTEST_SUCCESS)
    {
        return -1;
    }

    // Allocate memory for the quote - this simulates the real function's behavior
    *p_quote_size = sizeof(report) + 128; // Add some padding for mock quote format
    *pp_quote = (uint8_t *)malloc(*p_quote_size);
    if (!*pp_quote)
    {
        return -1;
    }

    // Fill with mock data
    memset(*pp_quote, 0, *p_quote_size);
    memcpy(*pp_quote, &report, sizeof(report));

    // Add mock quote header and signature
    memcpy(*pp_quote + sizeof(report), "MOCK_QUOTE_SIGNATURE", 20);

    printf("[MOCK] Generated TDX quote (%u bytes)\n", *p_quote_size);

    (void)p_qe_target_info;
    (void)qe_target_info_size;
    (void)p_att_key_id;
    (void)flags;

    return TDX_ATTEST_SUCCESS;
}

// Mock implementation for tdx_att_free_quote
void tdx_att_free_quote(uint8_t *p_quote)
{
    if (p_quote)
    {
        free(p_quote);
        printf("[MOCK] Freed TDX quote\n");
    }
}
#endif

// Helper function to print hex values
void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

// Helper function to calculate SHA-256 hash of a file
static int calculate_file_hash(const char *file_path, unsigned char *hash_output)
{
    int ret = -1;
    FILE *file = NULL;
    unsigned char *buffer = NULL;
    long file_size;

    // Open the file
    file = fopen(file_path, "rb");
    if (!file)
    {
        fprintf(stderr, "Failed to open file %s: %s\n", file_path, strerror(errno));
        return -1;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0)
    {
        // Empty file, compute hash of empty string
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Final(hash_output, &sha256);
        fclose(file);
        return 0;
    }

    // Allocate memory for the file content
    buffer = (unsigned char *)malloc(file_size);
    if (!buffer)
    {
        fprintf(stderr, "Memory allocation failed for %s\n", file_path);
        fclose(file);
        return -1;
    }

    // Read the file content
    if (fread(buffer, 1, file_size, file) != (size_t)file_size)
    {
        fprintf(stderr, "Failed to read file %s\n", file_path);
        free(buffer);
        fclose(file);
        return -1;
    }

    // Calculate SHA-256 hash of the file
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buffer, file_size);
    SHA256_Final(hash_output, &sha256);

    ret = 0;

    free(buffer);
    fclose(file);
    return ret;
}

// Compare function for qsort to sort directory entries
static int compare_dirents(const void *a, const void *b)
{
    return strcmp((*(struct dirent **)a)->d_name, (*(struct dirent **)b)->d_name);
}

// Calculate hash of a directory (including all files and subdirectories)
int calculate_directory_hash(const char *dir_path, unsigned char *hash_output)
{
    DIR *dir = NULL;
    struct dirent *entry;
    struct dirent **entries = NULL;
    int entry_count = 0;
    char file_path[PATH_MAX];
    unsigned char file_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;

    // Open the directory
    dir = opendir(dir_path);
    if (!dir)
    {
        fprintf(stderr, "Failed to open directory %s: %s\n", dir_path, strerror(errno));
        return -1;
    }

    // Count entries and allocate memory for sorting
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }
        entry_count++;
    }

    if (entry_count == 0)
    {
        // Empty directory, compute hash of empty string
        SHA256_Init(&sha256_ctx);
        SHA256_Final(hash_output, &sha256_ctx);
        closedir(dir);
        return 0;
    }

    // Rewind directory and store entries
    rewinddir(dir);
    entries = (struct dirent **)malloc(entry_count * sizeof(struct dirent *));
    if (!entries)
    {
        fprintf(stderr, "Memory allocation failed\n");
        closedir(dir);
        return -1;
    }

    int idx = 0;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        // Make a copy of the dirent structure
        struct dirent *entry_copy = (struct dirent *)malloc(sizeof(struct dirent));
        if (!entry_copy)
        {
            fprintf(stderr, "Memory allocation failed\n");
            for (int i = 0; i < idx; i++)
            {
                free(entries[i]);
            }
            free(entries);
            closedir(dir);
            return -1;
        }

        memcpy(entry_copy, entry, sizeof(struct dirent));
        entries[idx++] = entry_copy;
    }

    // Sort entries by name for consistent ordering
    qsort(entries, entry_count, sizeof(struct dirent *), compare_dirents);

    // Initialize SHA-256 context for directory hash
    SHA256_Init(&sha256_ctx);

    // Process each entry
    for (int i = 0; i < entry_count; i++)
    {
        entry = entries[i];

        // Construct full path
        snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);

        struct stat statbuf;
        if (stat(file_path, &statbuf) != 0)
        {
            fprintf(stderr, "Failed to stat %s: %s\n", file_path, strerror(errno));
            continue;
        }

        // Add entry name to directory hash
        SHA256_Update(&sha256_ctx, (unsigned char *)entry->d_name, strlen(entry->d_name));

        if (S_ISDIR(statbuf.st_mode))
        {
            // Recursively hash subdirectory
            if (calculate_directory_hash(file_path, file_hash) != 0)
            {
                fprintf(stderr, "Failed to hash directory %s\n", file_path);
                continue;
            }

            // Add subdirectory hash to directory hash
            SHA256_Update(&sha256_ctx, file_hash, SHA256_DIGEST_LENGTH);
            printf("  Added directory: %s\n", entry->d_name);
        }
        else if (S_ISREG(statbuf.st_mode))
        {
            // Hash regular file
            if (calculate_file_hash(file_path, file_hash) != 0)
            {
                fprintf(stderr, "Failed to hash file %s\n", file_path);
                continue;
            }

            // Add file hash to directory hash
            SHA256_Update(&sha256_ctx, file_hash, SHA256_DIGEST_LENGTH);
            printf("  Added file: %s\n", entry->d_name);
        }
    }

    // Finalize directory hash
    SHA256_Final(hash_output, &sha256_ctx);

    // Clean up
    for (int i = 0; i < entry_count; i++)
    {
        free(entries[i]);
    }
    free(entries);
    closedir(dir);

    return 0;
}

// Public API: Measure a path (file or directory) and extend the specified RTMR
int tdx_measure_and_extend(const char *path, int rtmr_index)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    struct stat path_stat;
    tdx_rtmr_event_t rtmr_event = {0};

    printf("Measuring: %s\n", path);

    if (stat(path, &path_stat) != 0)
    {
        fprintf(stderr, "Error: Cannot access %s: %s\n", path, strerror(errno));
        return -1;
    }

    // Calculate hash based on whether it's a file or directory
    if (S_ISDIR(path_stat.st_mode))
    {
        printf("Computing hash for directory: %s\n", path);
        if (calculate_directory_hash(path, hash) != 0)
        {
            fprintf(stderr, "Error: Failed to hash directory %s\n", path);
            return -1;
        }
    }
    else if (S_ISREG(path_stat.st_mode))
    {
        printf("Computing hash for file: %s\n", path);
        if (calculate_file_hash(path, hash) != 0)
        {
            fprintf(stderr, "Error: Failed to hash file %s\n", path);
            return -1;
        }
    }
    else
    {
        fprintf(stderr, "Error: %s is neither a regular file nor a directory\n", path);
        return -1;
    }

    print_hex("Computed hash", hash, SHA256_DIGEST_LENGTH);

    // Set up RTMR event for extending
    rtmr_event.version = 1;
    rtmr_event.rtmr_index = rtmr_index;
    rtmr_event.event_data_size = 0;

    memset(rtmr_event.extend_data, 0, TDX_EXTEND_RTMR_DATA_LEN);
    memcpy(rtmr_event.extend_data, hash,
           SHA256_DIGEST_LENGTH < TDX_EXTEND_RTMR_DATA_LEN ? SHA256_DIGEST_LENGTH : TDX_EXTEND_RTMR_DATA_LEN);

    // Extend RTMR with hash
    if (tdx_att_extend(&rtmr_event) != TDX_ATTEST_SUCCESS)
    {
        fprintf(stderr, "Error: Failed to extend RTMR%d\n", rtmr_index);
        return -1;
    }

    printf("✅ Successfully extended RTMR%d with hash of %s\n", rtmr_index, path);
    return 0;
}

// Public API: Generate a TDX Quote for remote attestation
// Function implementation to generate and save quote
int tdx_generate_and_save_quote(const uint8_t *report_data, size_t report_data_size,
                                const char *filename)
{
    tdx_report_data_t tdx_report_data = {{0}};
    uint8_t *p_quote_buf = NULL;
    uint32_t quote_size = 0;
    FILE *fptr = NULL;
    tdx_uuid_t selected_att_key_id = {0};

    // Use default filename if not provided
    const char *output_file = (filename != NULL) ? filename : "quote.dat";

    // Copy report data if provided
    if (report_data && report_data_size > 0)
    {
        if (report_data_size > TDX_REPORT_DATA_SIZE)
        {
            fprintf(stderr, "Error: Report data size (%zu) exceeds maximum (%d)\n",
                    report_data_size, TDX_REPORT_DATA_SIZE);
            return -1;
        }
        memcpy(tdx_report_data.d, report_data, report_data_size);
    }
    else
    {
        // Generate random report data if not provided
        srand(time(NULL));
        for (int i = 0; i < TDX_REPORT_DATA_SIZE; i++)
        {
            tdx_report_data.d[i] = rand();
        }
        printf("Generated random report data\n");
    }

    // Print report data for debugging
    printf("Report data used for quote:\n");
    for (size_t i = 0; i < TDX_REPORT_DATA_SIZE; i++)
    {
        if (i % 16 == 0)
            printf("\n  ");
        printf("%02x ", tdx_report_data.d[i]);
    }
    printf("\n");

    // Get TDX quote
    if (tdx_att_get_quote(&tdx_report_data, NULL, 0, &selected_att_key_id,
                          &p_quote_buf, &quote_size, 0) != TDX_ATTEST_SUCCESS)
    {
        fprintf(stderr, "Error: Failed to get TDX quote\n");
        return -1;
    }

    // Print quote info
    printf("Successfully generated TDX quote (%u bytes)\n", quote_size);

    // Save quote to file
    fptr = fopen(output_file, "wb");
    if (!fptr)
    {
        fprintf(stderr, "Error: Failed to open file for writing: %s\n", output_file);
        tdx_att_free_quote(p_quote_buf);
        return -1;
    }

    if (fwrite(p_quote_buf, quote_size, 1, fptr) != 1)
    {
        fprintf(stderr, "Error: Failed to write quote to file\n");
        fclose(fptr);
        tdx_att_free_quote(p_quote_buf);
        return -1;
    }

    fclose(fptr);
    printf("✅ TDX quote successfully saved to %s\n", output_file);

    // Free quote buffer
    tdx_att_free_quote(p_quote_buf);

    return 0;
}

// Command-line interface implementation
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <command> [options]\n\n", argv[0]);
        printf("Commands:\n");
        printf("  init [base_dir]         Initialize TDX measurements for all components\n");
        printf("  measure <path> <rtmr>   Measure a specific path and extend an RTMR register\n");
        printf("  quote [output_file]     Generate a TDX quote for remote attestation\n");
        printf("\n");
        printf("Options:\n");
        printf("  base_dir                Base directory for init (default: current directory)\n");
        printf("  path                    Path to file or directory to measure\n");
        printf("  rtmr                    RTMR register index (0-3)\n");
        printf("  output_file             Path to save quote (default: tdx_quote.bin)\n");
        return 1;
    }

    const char *command = argv[1];

    if (strcmp(command, "init") == 0)
    {
        const char *base_dir = ".";

        if (argc > 2)
        {
            base_dir = argv[2];
        }

        printf("===============================================\n");
        printf("TDX Initialization - Extending Measurements\n");
        printf("===============================================\n");
        printf("Base directory: %s\n", base_dir);

        // Measure and extend key tool (RTMR3)
        char key_tool_path[PATH_MAX];
        snprintf(key_tool_path, PATH_MAX, "%s/tapp-key-tool", base_dir);
        printf("\n[1/3] Measuring tapp-key-tool directory\n");
        if (tdx_measure_and_extend(key_tool_path, 3) != 0)
        {
            fprintf(stderr, "Failed to measure tapp-key-tool\n");
            return 1;
        }

        // Measure and extend business app (RTMR3)
        char business_app_path[PATH_MAX];
        snprintf(business_app_path, PATH_MAX, "%s/business-app", base_dir);
        printf("\n[2/3] Measuring business-app directory\n");
        if (tdx_measure_and_extend(business_app_path, 3) != 0)
        {
            fprintf(stderr, "Failed to measure business-app\n");
            return 1;
        }

        // Measure and extend init itself (RTMR3)
        printf("\n[3/3] Measuring init program itself\n");
        if (tdx_measure_and_extend(argv[0], 3) != 0)
        {
            fprintf(stderr, "Failed to measure init program\n");
            return 1;
        }

        printf("\n===============================================\n");
        printf("✅ Initialization complete! All components measured and RTMRs extended.\n");
        printf("===============================================\n");
    }
    else if (strcmp(command, "measure") == 0)
    {
        if (argc < 4)
        {
            fprintf(stderr, "Error: 'measure' command requires <path> and <rtmr> arguments\n");
            return 1;
        }

        const char *path = argv[2];
        int rtmr_index = atoi(argv[3]);

        if (rtmr_index < 0 || rtmr_index > 3)
        {
            fprintf(stderr, "Error: RTMR index must be 0-3\n");
            return 1;
        }

        printf("Measuring path '%s' and extending RTMR%d...\n", path, rtmr_index);

        if (tdx_measure_and_extend(path, rtmr_index) != 0)
        {
            fprintf(stderr, "Failed to measure path\n");
            return 1;
        }
    }
    else if (strcmp(command, "quote") == 0)
    {
        const char *output_file = "quote.dat";
        uint8_t report_data[TDX_REPORT_DATA_SIZE] = {0};
        size_t report_data_size = 0;

        // Process arguments
        for (int i = 2; i < argc; i++)
        {
            if (strncmp(argv[i], "-o=", 3) == 0 || strncmp(argv[i], "--output=", 9) == 0)
            {
                // Output file
                const char *arg = argv[i];
                const char *equals_pos = strchr(arg, '=');
                if (equals_pos)
                {
                    output_file = equals_pos + 1;
                }
            }
            else if (strncmp(argv[i], "-d=", 3) == 0 || strncmp(argv[i], "--data=", 7) == 0)
            {
                // Report data in hex format
                const char *arg = argv[i];
                const char *equals_pos = strchr(arg, '=');
                if (equals_pos)
                {
                    const char *hex_data = equals_pos + 1;
                    size_t hex_len = strlen(hex_data);

                    // Validation checks
                    if (hex_len % 2)
                    {
                        fprintf(stderr, "Error: Report data size is not even\n");
                        return 1;
                    }

                    if (hex_len / 2 > TDX_REPORT_DATA_SIZE)
                    {
                        fprintf(stderr, "Error: Report data size is too large\n");
                        return 1;
                    }

                    for (size_t j = 0; j < hex_len; j++)
                    {
                        if (!isxdigit(hex_data[j]))
                        {
                            fprintf(stderr, "Error: Invalid character in report data\n");
                            return 1;
                        }
                    }

                    // Convert hex string to binary
                    for (size_t j = 0; j < hex_len; j += 2)
                    {
                        char byte[3] = {hex_data[j], hex_data[j + 1], '\0'};
                        report_data[j / 2] = strtol(byte, NULL, 16);
                    }

                    report_data_size = hex_len / 2;
                }
            }
        }

        printf("Generating TDX quote...\n");

        if (tdx_generate_and_save_quote(
                report_data_size > 0 ? report_data : NULL,
                report_data_size,
                output_file) != 0)
        {
            fprintf(stderr, "Failed to generate and save TDX quote\n");
            return 1;
        }
    }
    else
    {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }

    return 0;
}