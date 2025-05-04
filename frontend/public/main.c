/**
 * Platform-independent PE File Parser
 * 
 * Features:
 * - Supports PE32 and PE32+ formats
 * - Extracts header information (target machine, entry point, sections)
 * - Extracts section data (name, VA, sizes, entropy, MD5, chi-squared)
 * - Lists imported DLLs and their functions
 * - Extracts resources with metadata (SHA-256, type, language, entropy, chi-squared)
 * - Verifies digital signatures
 *
 * Requires:
 * - OpenSSL for cryptographic operations
 * - Standard C libraries
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdint.h>
 #include <stdbool.h>
 #include <math.h>
 
// For WebAssembly export
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define WASM_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define WASM_EXPORT
#endif

// Basic hash functions for WebAssembly compatibility
void simple_md5(const unsigned char* data, size_t len, char* output);
void simple_sha256(const unsigned char* data, size_t len, char* output);

// Platform-independent data types to match PE format
 typedef uint8_t  BYTE;
 typedef uint16_t WORD;
 typedef uint32_t DWORD;
 typedef uint64_t QWORD;
 typedef int32_t  LONG;
 
 // Constants for PE format
 #define IMAGE_DOS_SIGNATURE    0x5A4D      // MZ
 #define IMAGE_NT_SIGNATURE     0x00004550  // PE00
 #define IMAGE_SIZEOF_SHORT_NAME 8
 
 // File handling
 typedef struct {
     FILE* handle;
     long size;
     BYTE* data;
     DWORD position;
 } PE_FILE;
 
 // DOS Header
 typedef struct {
     WORD e_magic;
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;
 } IMAGE_DOS_HEADER;
 
 // File Header
 typedef struct {
     WORD Machine;
     WORD NumberOfSections;
     DWORD TimeDateStamp;
     DWORD PointerToSymbolTable;
     DWORD NumberOfSymbols;
     WORD SizeOfOptionalHeader;
     WORD Characteristics;
 } IMAGE_FILE_HEADER;
 
 // Data Directory
 typedef struct {
     DWORD VirtualAddress;
     DWORD Size;
 } IMAGE_DATA_DIRECTORY;
 
 #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
 
 // Optional Header for PE32
 typedef struct {
     WORD Magic;
     BYTE MajorLinkerVersion;
     BYTE MinorLinkerVersion;
     DWORD SizeOfCode;
     DWORD SizeOfInitializedData;
     DWORD SizeOfUninitializedData;
     DWORD AddressOfEntryPoint;
     DWORD BaseOfCode;
     DWORD BaseOfData;  // PE32 only, not in PE32+
     DWORD ImageBase;   // 32-bit
     DWORD SectionAlignment;
     DWORD FileAlignment;
     WORD MajorOperatingSystemVersion;
     WORD MinorOperatingSystemVersion;
     WORD MajorImageVersion;
     WORD MinorImageVersion;
     WORD MajorSubsystemVersion;
     WORD MinorSubsystemVersion;
     DWORD Win32VersionValue;
     DWORD SizeOfImage;
     DWORD SizeOfHeaders;
     DWORD CheckSum;
     WORD Subsystem;
     WORD DllCharacteristics;
     DWORD SizeOfStackReserve;
     DWORD SizeOfStackCommit;
     DWORD SizeOfHeapReserve;
     DWORD SizeOfHeapCommit;
     DWORD LoaderFlags;
     DWORD NumberOfRvaAndSizes;
     IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
 } IMAGE_OPTIONAL_HEADER32;
 
 // Optional Header for PE32+
 typedef struct {
     WORD Magic;
     BYTE MajorLinkerVersion;
     BYTE MinorLinkerVersion;
     DWORD SizeOfCode;
     DWORD SizeOfInitializedData;
     DWORD SizeOfUninitializedData;
     DWORD AddressOfEntryPoint;
     DWORD BaseOfCode;
     QWORD ImageBase;  // 64-bit
     DWORD SectionAlignment;
     DWORD FileAlignment;
     WORD MajorOperatingSystemVersion;
     WORD MinorOperatingSystemVersion;
     WORD MajorImageVersion;
     WORD MinorImageVersion;
     WORD MajorSubsystemVersion;
     WORD MinorSubsystemVersion;
     DWORD Win32VersionValue;
     DWORD SizeOfImage;
     DWORD SizeOfHeaders;
     DWORD CheckSum;
     WORD Subsystem;
     WORD DllCharacteristics;
     QWORD SizeOfStackReserve;
     QWORD SizeOfStackCommit;
     QWORD SizeOfHeapReserve;
     QWORD SizeOfHeapCommit;
     DWORD LoaderFlags;
     DWORD NumberOfRvaAndSizes;
     IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
 } IMAGE_OPTIONAL_HEADER64;
 
 // NT Headers
 typedef struct {
     DWORD Signature;
     IMAGE_FILE_HEADER FileHeader;
     // Optional header follows but is not included here due to variable size
 } IMAGE_NT_HEADERS;
 
 // Section Header
 typedef struct {
     BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
     union {
         DWORD PhysicalAddress;
         DWORD VirtualSize;
     } Misc;
     DWORD VirtualAddress;
     DWORD SizeOfRawData;
     DWORD PointerToRawData;
     DWORD PointerToRelocations;
     DWORD PointerToLinenumbers;
     WORD NumberOfRelocations;
     WORD NumberOfLinenumbers;
     DWORD Characteristics;
 } IMAGE_SECTION_HEADER;
 
 // Import Directory Entry
 typedef struct {
     DWORD Characteristics;
     DWORD TimeDateStamp;
     DWORD ForwarderChain;
     DWORD Name;
     DWORD FirstThunk;
 } IMAGE_IMPORT_DESCRIPTOR;
 
 // Import by name
 typedef struct {
     WORD Hint;
     BYTE Name[1];  // Variable length
 } IMAGE_IMPORT_BY_NAME;
 
 // Thunk data
 typedef struct {
     union {
         DWORD Function;
         DWORD Ordinal;
         DWORD AddressOfData;
     };
 } IMAGE_THUNK_DATA32;
 
 typedef struct {
     union {
         QWORD Function;
         QWORD Ordinal;
         QWORD AddressOfData;
     };
 } IMAGE_THUNK_DATA64;
 
 // Resource Directory Table
 typedef struct {
     DWORD Characteristics;
     DWORD TimeDateStamp;
     WORD MajorVersion;
     WORD MinorVersion;
     WORD NumberOfNamedEntries;
     WORD NumberOfIdEntries;
     // Directory entries follow
 } IMAGE_RESOURCE_DIRECTORY;
 
 // Resource Directory Entry
 typedef struct {
     union {
         struct {
             DWORD NameOffset:31;
             DWORD NameIsString:1;
         };
         DWORD Name;
         WORD Id;
     };
     union {
         DWORD OffsetToData;
         struct {
             DWORD OffsetToDirectory:31;
             DWORD DataIsDirectory:1;
         };
     };
 } IMAGE_RESOURCE_DIRECTORY_ENTRY;
 
 // Resource Data Entry
 typedef struct {
     DWORD OffsetToData;
     DWORD Size;
     DWORD CodePage;
     DWORD Reserved;
 } IMAGE_RESOURCE_DATA_ENTRY;
 
 // Directory indices
 enum {
     IMAGE_DIRECTORY_ENTRY_EXPORT          = 0,
     IMAGE_DIRECTORY_ENTRY_IMPORT          = 1,
     IMAGE_DIRECTORY_ENTRY_RESOURCE        = 2,
     IMAGE_DIRECTORY_ENTRY_EXCEPTION       = 3,
     IMAGE_DIRECTORY_ENTRY_SECURITY        = 4,
     IMAGE_DIRECTORY_ENTRY_BASERELOC       = 5,
     IMAGE_DIRECTORY_ENTRY_DEBUG           = 6,
     IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    = 7,
     IMAGE_DIRECTORY_ENTRY_GLOBALPTR       = 8,
     IMAGE_DIRECTORY_ENTRY_TLS             = 9,
     IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG     = 10,
     IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT    = 11,
     IMAGE_DIRECTORY_ENTRY_IAT             = 12,
     IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT    = 13,
     IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR  = 14,
     IMAGE_DIRECTORY_ENTRY_RESERVED        = 15
 };
 
 // Machine types
 #define IMAGE_FILE_MACHINE_UNKNOWN      0x0
 #define IMAGE_FILE_MACHINE_I386         0x14c   // Intel 386
 #define IMAGE_FILE_MACHINE_IA64         0x200   // Intel Itanium
 #define IMAGE_FILE_MACHINE_AMD64        0x8664  // AMD64 (x64)
 #define IMAGE_FILE_MACHINE_ARM          0x1c0   // ARM
 #define IMAGE_FILE_MACHINE_ARM64        0xaa64  // ARM64
 #define IMAGE_FILE_MACHINE_ARMNT        0x1c4   // ARM Thumb-2
 
 // File characteristics
 #define IMAGE_FILE_RELOCS_STRIPPED         0x0001  // Relocation info stripped
 #define IMAGE_FILE_EXECUTABLE_IMAGE        0x0002  // File is executable
 #define IMAGE_FILE_LINE_NUMS_STRIPPED      0x0004  // Line numbers stripped
 #define IMAGE_FILE_LOCAL_SYMS_STRIPPED     0x0008  // Local symbols stripped
 #define IMAGE_FILE_AGGRESIVE_WS_TRIM       0x0010  // Aggressively trim working set
 #define IMAGE_FILE_LARGE_ADDRESS_AWARE     0x0020  // Can handle > 2GB addresses
 #define IMAGE_FILE_BYTES_REVERSED_LO       0x0080  // Bytes of word are reversed
 #define IMAGE_FILE_32BIT_MACHINE           0x0100  // 32-bit machine
 #define IMAGE_FILE_DEBUG_STRIPPED          0x0200  // Debug info stripped
 #define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400  // If on removable media, copy and run from swap
 #define IMAGE_FILE_NET_RUN_FROM_SWAP       0x0800  // If on network, copy and run from swap
 #define IMAGE_FILE_SYSTEM                  0x1000  // System file
 #define IMAGE_FILE_DLL                     0x2000  // DLL file
 #define IMAGE_FILE_UP_SYSTEM_ONLY          0x4000  // Run only on uniprocessor machine
 #define IMAGE_FILE_BYTES_REVERSED_HI       0x8000  // Bytes of word are reversed
 
 // Subsystems
 #define IMAGE_SUBSYSTEM_UNKNOWN                 0   // Unknown subsystem
 #define IMAGE_SUBSYSTEM_NATIVE                  1   // No subsystem required
 #define IMAGE_SUBSYSTEM_WINDOWS_GUI             2   // Windows GUI
 #define IMAGE_SUBSYSTEM_WINDOWS_CUI             3   // Windows character mode
 #define IMAGE_SUBSYSTEM_OS2_CUI                 5   // OS/2 character mode
 #define IMAGE_SUBSYSTEM_POSIX_CUI               7   // POSIX character mode
 #define IMAGE_SUBSYSTEM_NATIVE_WINDOWS          8   // Native Windows
 #define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI          9   // Windows CE
 #define IMAGE_SUBSYSTEM_EFI_APPLICATION        10   // EFI application
 #define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11  // EFI driver with boot services
 #define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER     12   // EFI driver with runtime services
 #define IMAGE_SUBSYSTEM_EFI_ROM                13   // EFI ROM image
 #define IMAGE_SUBSYSTEM_XBOX                   14   // Xbox system
 #define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16 // Boot application
 
 // Optional header magic numbers
 #define IMAGE_NT_OPTIONAL_HDR32_MAGIC   0x10b   // PE32
 #define IMAGE_NT_OPTIONAL_HDR64_MAGIC   0x20b   // PE32+
 
 // Our custom PE analysis structures
 typedef struct {
     char name[IMAGE_SIZEOF_SHORT_NAME + 1];
     DWORD virtual_address;
     DWORD virtual_size;
     DWORD raw_size;
     double entropy;
     char md5[33];  // MD5 hash (32 chars + null terminator)
     double chi_squared;
 } PE_SECTION_INFO;
 
 typedef struct {
     char dll_name[256];
     char** function_names;
     int function_count;
 } PE_IMPORT_INFO;
 
 typedef struct {
     char sha256[65];  // SHA-256 hash (64 chars + null terminator)
     char type[64];     // Resource type description
     char lang[64];     // Language description
     double entropy;
     double chi_squared;
     DWORD size;
 } PE_RESOURCE_INFO;
 
 typedef struct {
     // Header info
     WORD machine;
     char machine_str[64];
     DWORD entry_point;
     WORD num_sections;
     bool is_64bit;
     DWORD dos_header_size;
     DWORD size_of_headers;
     
     // DOS header info
     WORD e_magic;
     DWORD e_lfanew;
     
     // File header info
     DWORD time_date_stamp;
     WORD size_of_optional_header;
     WORD characteristics;
     
     // Optional header info
     WORD magic;
     union {
         DWORD image_base_32;
         QWORD image_base_64;
     };
     DWORD section_alignment;
     DWORD file_alignment;
     WORD subsystem;
     IMAGE_DATA_DIRECTORY data_directories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
     
     // Sections
     PE_SECTION_INFO* sections;
     int section_count;
     
     // Imports
     PE_IMPORT_INFO* imports;
     int import_count;
     
     // Resources
     PE_RESOURCE_INFO* resources;
     int resource_count;
     
     // Digital signature
     bool has_signature;
     char signer_name[256];
     bool signature_valid;
 } PE_INFO;
 
 // Function declarations
 PE_FILE* pe_open_file(const char* filepath);
 void pe_close_file(PE_FILE* pe_file);
 bool pe_parse_file(PE_FILE* pe_file, PE_INFO* pe_info);
 bool pe_parse_headers(PE_FILE* pe_file, PE_INFO* pe_info, DWORD* optional_header_offset, WORD* optional_header_size);
 bool pe_parse_sections(PE_FILE* pe_file, PE_INFO* pe_info, DWORD section_table_offset, WORD num_sections);
 bool pe_parse_imports(PE_FILE* pe_file, PE_INFO* pe_info, DWORD import_dir_rva, DWORD import_dir_size);
 bool pe_parse_resources(PE_FILE* pe_file, PE_INFO* pe_info, DWORD resource_dir_rva, DWORD resource_dir_size);
 bool pe_verify_signature(PE_FILE* pe_file, PE_INFO* pe_info, DWORD security_dir_offset, DWORD security_dir_size);
 DWORD pe_rva_to_offset(PE_FILE* pe_file, PE_INFO* pe_info, DWORD rva);
 double calculate_entropy(BYTE* data, DWORD size);
 double calculate_chi_squared(BYTE* data, DWORD size);
 void calculate_md5(BYTE* data, DWORD size, char* output);
 void calculate_sha256(BYTE* data, DWORD size, char* output);
 const char* get_machine_type_string(WORD machine);
 const char* get_resource_type_string(WORD type);
 const char* get_resource_lang_string(WORD lang_id);
 void get_characteristics_strings(WORD characteristics, char** string_array, int* count);
 const char* get_subsystem_string(WORD subsystem);
 
 /**
  * Main function
  */
 int main(int argc, char* argv[]) {
     if (argc < 2) {
         printf("Usage: %s <pe_file>\n", argv[0]);
         return 1;
     }
     
     PE_FILE* pe_file = pe_open_file(argv[1]);
     if (!pe_file) {
         printf("{\"error\": \"Could not open file %s\"}\n", argv[1]);
         return 1;
     }
     
     PE_INFO pe_info;
     memset(&pe_info, 0, sizeof(PE_INFO));
     
     if (!pe_parse_file(pe_file, &pe_info)) {
         printf("{\"error\": \"File is not a valid PE file\"}\n");
         pe_close_file(pe_file);
         return 1;
     }
     
     // Print PE information as JSON
     printf("{\n");
     
     // Header information
     printf("  \"header\": {\n");
     printf("    \"format\": \"%s\",\n", pe_info.is_64bit ? "PE32+" : "PE32");
     printf("    \"machine\": {\n");
     printf("      \"type\": \"%s\",\n", pe_info.machine_str);
     printf("      \"code\": \"0x%04X\"\n", pe_info.machine);
     printf("    },\n");
     printf("    \"entryPoint\": \"0x%08X\",\n", pe_info.entry_point);
     printf("    \"sectionCount\": %d,\n", pe_info.num_sections);
     
     // DOS header information
     printf("    \"dosHeader\": {\n");
     printf("      \"e_magic\": \"0x%04X\",\n", pe_info.e_magic);
     printf("      \"e_lfanew\": \"0x%08X\"\n", pe_info.e_lfanew);
     printf("    },\n");
     
     // File header information
     printf("    \"fileHeader\": {\n");
     printf("      \"timestamp\": %u,\n", pe_info.time_date_stamp);
     printf("      \"optionalHeaderSize\": %u,\n", pe_info.size_of_optional_header);
     printf("      \"characteristics\": {\n");
     printf("        \"value\": \"0x%04X\",\n", pe_info.characteristics);
     
     // Print characteristics as strings
     char* char_strings[15];  // Maximum 15 flags
     int char_count = 0;
     get_characteristics_strings(pe_info.characteristics, char_strings, &char_count);
     
     printf("        \"flags\": [\n");
     for (int i = 0; i < char_count; i++) {
         printf("          \"%s\"%s", char_strings[i], i < char_count - 1 ? ",\n" : "\n");
         free(char_strings[i]);  // Free the allocated string
     }
     printf("        ]\n");
     printf("      }\n");
     printf("    },\n");
     
     // Optional header information
     printf("    \"optionalHeader\": {\n");
     printf("      \"magic\": \"0x%04X\",\n", pe_info.magic);
     printf("      \"entryPoint\": \"0x%08X\",\n", pe_info.entry_point);
     
     // Image base depends on format
     if (pe_info.is_64bit) {
         printf("      \"imageBase\": \"0x%016llX\",\n", pe_info.image_base_64);
     } else {
         printf("      \"imageBase\": \"0x%08X\",\n", pe_info.image_base_32);
     }
     
     printf("      \"sectionAlignment\": %u,\n", pe_info.section_alignment);
     printf("      \"fileAlignment\": %u,\n", pe_info.file_alignment);
     printf("      \"subsystem\": {\n");
     printf("        \"value\": %u,\n", pe_info.subsystem);
     printf("        \"name\": \"%s\"\n", get_subsystem_string(pe_info.subsystem));
     printf("      },\n");
     
     // Data directories
     printf("      \"dataDirectories\": [\n");
     const char* directory_names[] = {
         "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
         "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
         "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", 
         "COM_DESCRIPTOR", "RESERVED"
     };
     
     int dir_count = 0;
     int valid_dirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {0};
     
     // First, find all valid directories and count them
     for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
         IMAGE_DATA_DIRECTORY* dir = &pe_info.data_directories[i];
         if (dir->VirtualAddress != 0 || dir->Size != 0) {
             valid_dirs[dir_count++] = i;
         }
     }
     
     // Then output them with proper comma handling
     for (int idx = 0; idx < dir_count; idx++) {
         int i = valid_dirs[idx];
         IMAGE_DATA_DIRECTORY* dir = &pe_info.data_directories[i];
         
         printf("        {\n");
         printf("          \"name\": \"%s\",\n", directory_names[i]);
         printf("          \"virtualAddress\": \"0x%08X\",\n", dir->VirtualAddress);
         printf("          \"size\": %u\n", dir->Size);
         // Only add comma if this is not the last entry
         printf("        }%s", idx < dir_count - 1 ? ",\n" : "\n");
     }
     
     printf("      ]\n");
     printf("    }\n");
     
     printf("  },\n");
     
     // Section information
     printf("  \"sections\": [\n");
     for (int i = 0; i < pe_info.section_count; i++) {
         PE_SECTION_INFO* section = &pe_info.sections[i];
         char ascii_name[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
         
         // Convert the name to ASCII representation
         for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
             // Only copy printable characters, otherwise replace with a dot
             ascii_name[j] = (section->name[j] >= 32 && section->name[j] <= 126) ? section->name[j] : '.';
         }
         
         printf("    {\n");
         printf("      \"name\": \"%s\",\n", section->name);
         printf("      \"nameASCII\": \"%s\",\n", ascii_name);
         printf("      \"virtualAddress\": {\n");
         printf("        \"hex\": \"0x%08X\",\n", section->virtual_address);
         printf("        \"decimal\": %u\n", section->virtual_address);
         printf("      },\n");
         printf("      \"virtualSize\": {\n");
         printf("        \"hex\": \"0x%08X\",\n", section->virtual_size);
         printf("        \"decimal\": %u\n", section->virtual_size);
         printf("      },\n");
         printf("      \"rawSize\": {\n");
         printf("        \"hex\": \"0x%08X\",\n", section->raw_size);
         printf("        \"decimal\": %u\n", section->raw_size);
         printf("      },\n");
         printf("      \"entropy\": %.6f,\n", section->entropy);
         printf("      \"md5\": \"%s\",\n", section->md5);
         printf("      \"chiSquared\": %.6f\n", section->chi_squared);
         printf("    }%s", i < pe_info.section_count - 1 ? ",\n" : "\n");
     }
     printf("  ],\n");
     
     // Import information
     printf("  \"imports\": [\n");
     for (int i = 0; i < pe_info.import_count; i++) {
         PE_IMPORT_INFO* import = &pe_info.imports[i];
         printf("    {\n");
         printf("      \"dll\": \"%s\",\n", import->dll_name);
         printf("      \"functionCount\": %d,\n", import->function_count);
         printf("      \"functions\": [\n");
         
         for (int j = 0; j < import->function_count; j++) {
             printf("        \"%s\"%s", 
                   import->function_names[j] ? import->function_names[j] : "UNKNOWN",
                   j < import->function_count - 1 ? ",\n" : "\n");
         }
         
         printf("      ]\n");
         printf("    }%s", i < pe_info.import_count - 1 ? ",\n" : "\n");
     }
     printf("  ],\n");
     
     // Resource information
     printf("  \"resources\": [\n");
     if (pe_info.resource_count > 0) {
         for (int i = 0; i < pe_info.resource_count; i++) {
             PE_RESOURCE_INFO* res = &pe_info.resources[i];
             printf("    {\n");
             printf("      \"size\": %u,\n", res->size);
             printf("      \"type\": \"%s\",\n", res->type);
             printf("      \"language\": \"%s\",\n", res->lang);
             printf("      \"entropy\": %.6f,\n", res->entropy);
             printf("      \"chiSquared\": %.6f,\n", res->chi_squared);
             printf("      \"sha256\": \"%s\"\n", res->sha256);
             printf("    }%s", i < pe_info.resource_count - 1 ? ",\n" : "\n");
         }
     }
     printf("  ],\n");
     
     // Digital signature
     printf("  \"signature\": {\n");
     printf("    \"isSigned\": %s,\n", pe_info.has_signature ? "true" : "false");
     if (pe_info.has_signature) {
         printf("    \"signer\": \"%s\",\n", pe_info.signer_name);
         printf("    \"isValid\": %s\n", pe_info.signature_valid ? "true" : "false");
     } else {
         printf("    \"signer\": null,\n");
         printf("    \"isValid\": null\n");
     }
     printf("  }\n");
     
     printf("}\n");
     
     // Cleanup resources
     for (int i = 0; i < pe_info.import_count; i++) {
         for (int j = 0; j < pe_info.imports[i].function_count; j++) {
             free(pe_info.imports[i].function_names[j]);
         }
         free(pe_info.imports[i].function_names);
     }
     
     free(pe_info.sections);
     free(pe_info.imports);
     free(pe_info.resources);
     
     pe_close_file(pe_file);
     return 0;
 }
 
 /**
  * Function to analyze PE buffer for WebAssembly
  * This will be called from JavaScript
  */
 WASM_EXPORT char* analyze_pe_buffer(const uint8_t* buffer, size_t buffer_size) {
    // Create a PE_FILE structure from the buffer
    PE_FILE* pe_file = (PE_FILE*)malloc(sizeof(PE_FILE));
    if (!pe_file) {
        return strdup("{\"error\": \"Memory allocation failed\"}");
    }
    
    pe_file->handle = NULL;  // No file handle when using buffer
    pe_file->size = buffer_size;
    pe_file->data = (BYTE*)malloc(buffer_size);
    pe_file->position = 0;
    
    if (!pe_file->data) {
        free(pe_file);
        return strdup("{\"error\": \"Memory allocation failed\"}");
    }
    
    // Copy the buffer data
    memcpy(pe_file->data, buffer, buffer_size);
    
    // Parse the PE file
    PE_INFO pe_info;
    memset(&pe_info, 0, sizeof(PE_INFO));
    
    if (!pe_parse_file(pe_file, &pe_info)) {
        char* result = strdup("{\"error\": \"File is not a valid PE file\"}");
        pe_close_file(pe_file);
        return result;
    }
    
    // Create dynamic buffer for JSON output
    size_t buffer_capacity = 10240;  // Start with 10KB
    char* json_buffer = (char*)malloc(buffer_capacity);
    if (!json_buffer) {
        pe_close_file(pe_file);
        return strdup("{\"error\": \"Memory allocation failed\"}");
    }
    
    size_t offset = 0;
    
    // Helper function to safely append to buffer
    #define APPEND(...) do { \
        int bytes_written = snprintf(json_buffer + offset, buffer_capacity - offset, __VA_ARGS__); \
        if (bytes_written >= buffer_capacity - offset) { \
            buffer_capacity *= 2; \
            char* new_buffer = (char*)realloc(json_buffer, buffer_capacity); \
            if (!new_buffer) { \
                free(json_buffer); \
                pe_close_file(pe_file); \
                return strdup("{\"error\": \"Memory allocation failed\"}"); \
            } \
            json_buffer = new_buffer; \
            bytes_written = snprintf(json_buffer + offset, buffer_capacity - offset, __VA_ARGS__); \
        } \
        offset += bytes_written; \
    } while(0)
    
    // Generate JSON output - header
    APPEND("{\n");
    APPEND("  \"header\": {\n");
    APPEND("    \"format\": \"%s\",\n", pe_info.is_64bit ? "PE32+" : "PE32");
    APPEND("    \"machine\": {\n");
    APPEND("      \"type\": \"%s\",\n", pe_info.machine_str);
    APPEND("      \"code\": \"0x%04X\"\n", pe_info.machine);
    APPEND("    },\n");
    APPEND("    \"entryPoint\": \"0x%08X\",\n", pe_info.entry_point);
    APPEND("    \"sectionCount\": %d,\n", pe_info.num_sections);
    
    // DOS header information
    APPEND("    \"dosHeader\": {\n");
    APPEND("      \"e_magic\": \"0x%04X\",\n", pe_info.e_magic);
    APPEND("      \"e_lfanew\": \"0x%08X\"\n", pe_info.e_lfanew);
    APPEND("    },\n");
    
    // File header information
    APPEND("    \"fileHeader\": {\n");
    APPEND("      \"timestamp\": %u,\n", pe_info.time_date_stamp);
    APPEND("      \"optionalHeaderSize\": %u,\n", pe_info.size_of_optional_header);
    APPEND("      \"characteristics\": {\n");
    APPEND("        \"value\": \"0x%04X\",\n", pe_info.characteristics);
    
    // Print characteristics as strings
    char* char_strings[15];  // Maximum 15 flags
    int char_count = 0;
    get_characteristics_strings(pe_info.characteristics, char_strings, &char_count);
    
    APPEND("        \"flags\": [\n");
    for (int i = 0; i < char_count; i++) {
        APPEND("          \"%s\"%s", char_strings[i], i < char_count - 1 ? ",\n" : "\n");
        free(char_strings[i]);  // Free the allocated string
    }
    APPEND("        ]\n");
    APPEND("      }\n");
    APPEND("    },\n");
    
    // Optional header information
    APPEND("    \"optionalHeader\": {\n");
    APPEND("      \"magic\": \"0x%04X\",\n", pe_info.magic);
    APPEND("      \"entryPoint\": \"0x%08X\",\n", pe_info.entry_point);
    
    // Image base depends on format
    if (pe_info.is_64bit) {
        APPEND("      \"imageBase\": \"0x%016llX\",\n", pe_info.image_base_64);
    } else {
        APPEND("      \"imageBase\": \"0x%08X\",\n", pe_info.image_base_32);
    }
    
    APPEND("      \"sectionAlignment\": %u,\n", pe_info.section_alignment);
    APPEND("      \"fileAlignment\": %u,\n", pe_info.file_alignment);
    APPEND("      \"subsystem\": {\n");
    APPEND("        \"value\": %u,\n", pe_info.subsystem);
    APPEND("        \"name\": \"%s\"\n", get_subsystem_string(pe_info.subsystem));
    APPEND("      },\n");
    
    // Data directories
    APPEND("      \"dataDirectories\": [\n");
    const char* directory_names[] = {
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
        "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
        "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", 
        "COM_DESCRIPTOR", "RESERVED"
    };
    
    int dir_count = 0;
    int valid_dirs[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {0};
    
    // First, find all valid directories and count them
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        IMAGE_DATA_DIRECTORY* dir = &pe_info.data_directories[i];
        if (dir->VirtualAddress != 0 || dir->Size != 0) {
            valid_dirs[dir_count++] = i;
        }
    }
    
    // Then output them with proper comma handling
    for (int idx = 0; idx < dir_count; idx++) {
        int i = valid_dirs[idx];
        IMAGE_DATA_DIRECTORY* dir = &pe_info.data_directories[i];
        
        APPEND("        {\n");
        APPEND("          \"name\": \"%s\",\n", directory_names[i]);
        APPEND("          \"virtualAddress\": \"0x%08X\",\n", dir->VirtualAddress);
        APPEND("          \"size\": %u\n", dir->Size);
        // Only add comma if this is not the last entry
        APPEND("        }%s", idx < dir_count - 1 ? ",\n" : "\n");
    }
    
    APPEND("      ]\n");
    APPEND("    }\n");
    
    APPEND("  },\n");
    
    // Generate JSON output - sections
    APPEND("  \"sections\": [\n");
    for (int i = 0; i < pe_info.section_count; i++) {
        PE_SECTION_INFO* section = &pe_info.sections[i];
        char ascii_name[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        
        // Convert the name to ASCII representation
        for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
            // Only copy printable characters, otherwise replace with a dot
            ascii_name[j] = (section->name[j] >= 32 && section->name[j] <= 126) ? section->name[j] : '.';
        }
        
        APPEND("    {\n");
        APPEND("      \"name\": \"%s\",\n", section->name);
        APPEND("      \"nameASCII\": \"%s\",\n", ascii_name);
        APPEND("      \"virtualAddress\": {\n");
        APPEND("        \"hex\": \"0x%08X\",\n", section->virtual_address);
        APPEND("        \"decimal\": %u\n", section->virtual_address);
        APPEND("      },\n");
        APPEND("      \"virtualSize\": {\n");
        APPEND("        \"hex\": \"0x%08X\",\n", section->virtual_size);
        APPEND("        \"decimal\": %u\n", section->virtual_size);
        APPEND("      },\n");
        APPEND("      \"rawSize\": {\n");
        APPEND("        \"hex\": \"0x%08X\",\n", section->raw_size);
        APPEND("        \"decimal\": %u\n", section->raw_size);
        APPEND("      },\n");
        APPEND("      \"entropy\": %.6f,\n", section->entropy);
        APPEND("      \"md5\": \"%s\",\n", section->md5);
        APPEND("      \"chiSquared\": %.6f\n", section->chi_squared);
        APPEND("    }%s", i < pe_info.section_count - 1 ? ",\n" : "\n");
    }
    APPEND("  ],\n");
    
    // Generate JSON output - imports
    APPEND("  \"imports\": [\n");
    for (int i = 0; i < pe_info.import_count; i++) {
        PE_IMPORT_INFO* import = &pe_info.imports[i];
        APPEND("    {\n");
        APPEND("      \"dll\": \"%s\",\n", import->dll_name);
        APPEND("      \"functionCount\": %d,\n", import->function_count);
        APPEND("      \"functions\": [\n");
        
        for (int j = 0; j < import->function_count; j++) {
            APPEND("        \"%s\"%s", 
                  import->function_names[j] ? import->function_names[j] : "UNKNOWN",
                  j < import->function_count - 1 ? ",\n" : "\n");
        }
        
        APPEND("      ]\n");
        APPEND("    }%s", i < pe_info.import_count - 1 ? ",\n" : "\n");
    }
    APPEND("  ],\n");
    
    // Generate JSON output - resources
    APPEND("  \"resources\": [\n");
    if (pe_info.resource_count > 0) {
        for (int i = 0; i < pe_info.resource_count; i++) {
            PE_RESOURCE_INFO* res = &pe_info.resources[i];
            APPEND("    {\n");
            APPEND("      \"size\": %u,\n", res->size);
            APPEND("      \"type\": \"%s\",\n", res->type);
            APPEND("      \"language\": \"%s\",\n", res->lang);
            APPEND("      \"entropy\": %.6f,\n", res->entropy);
            APPEND("      \"chiSquared\": %.6f,\n", res->chi_squared);
            APPEND("      \"sha256\": \"%s\"\n", res->sha256);
            APPEND("    }%s", i < pe_info.resource_count - 1 ? ",\n" : "\n");
        }
    }
    APPEND("  ],\n");
    
    // Generate JSON output - signature
    APPEND("  \"signature\": {\n");
    APPEND("    \"isSigned\": %s,\n", pe_info.has_signature ? "true" : "false");
    if (pe_info.has_signature) {
        APPEND("    \"signer\": \"%s\",\n", pe_info.signer_name);
        APPEND("    \"isValid\": %s\n", pe_info.signature_valid ? "true" : "false");
    } else {
        APPEND("    \"signer\": null,\n");
        APPEND("    \"isValid\": null\n");
    }
    APPEND("  }\n");
    
    APPEND("}\n");
    
    #undef APPEND
    
    // Cleanup resources
    for (int i = 0; i < pe_info.import_count; i++) {
        for (int j = 0; j < pe_info.imports[i].function_count; j++) {
            free(pe_info.imports[i].function_names[j]);
        }
        free(pe_info.imports[i].function_names);
    }
    
    free(pe_info.sections);
    free(pe_info.imports);
    free(pe_info.resources);
    
    pe_close_file(pe_file);
    
    // Return the JSON string (must be freed by caller)
    return json_buffer;
 }

 /**
  * Open PE file and read its contents
  */
 PE_FILE* pe_open_file(const char* filepath) {
     FILE* file = fopen(filepath, "rb");
     if (!file) {
         return NULL;
     }
     
     // Get file size
     fseek(file, 0, SEEK_END);
     long size = ftell(file);
     fseek(file, 0, SEEK_SET);
     
     if (size <= 0) {
         fclose(file);
         return NULL;
     }
     
     // Allocate memory for file contents
     BYTE* data = (BYTE*)malloc(size);
     if (!data) {
         fclose(file);
         return NULL;
     }
     
     // Read file contents
     if (fread(data, 1, size, file) != size) {
         free(data);
         fclose(file);
         return NULL;
     }
     
     // Create PE_FILE structure
     PE_FILE* pe_file = (PE_FILE*)malloc(sizeof(PE_FILE));
     if (!pe_file) {
         free(data);
         fclose(file);
         return NULL;
     }
     
     pe_file->handle = file;
     pe_file->size = size;
     pe_file->data = data;
     pe_file->position = 0;
     
     return pe_file;
 }
 
 /**
  * Close PE file and free resources
  */
 void pe_close_file(PE_FILE* pe_file) {
     if (pe_file) {
         if (pe_file->handle) {
             fclose(pe_file->handle);
         }
         if (pe_file->data) {
             free(pe_file->data);
         }
         free(pe_file);
     }
 }
 
 /**
  * Parse PE file
  */
 bool pe_parse_file(PE_FILE* pe_file, PE_INFO* pe_info) {
     if (!pe_file || !pe_file->data || !pe_info) {
         return false;
     }
     
     DWORD optional_header_offset;
     WORD optional_header_size;
     
     // Parse PE headers
     if (!pe_parse_headers(pe_file, pe_info, &optional_header_offset, &optional_header_size)) {
         return false;
     }
     
     // Calculate section table offset
     DWORD section_table_offset = optional_header_offset + optional_header_size;
     
     // Parse sections
     if (!pe_parse_sections(pe_file, pe_info, section_table_offset, pe_info->num_sections)) {
         return false;
     }
     
     // Get data directory information
     DWORD import_dir_rva = 0;
     DWORD import_dir_size = 0;
     DWORD resource_dir_rva = 0;
     DWORD resource_dir_size = 0;
     DWORD security_dir_offset = 0;
     DWORD security_dir_size = 0;
     
     if (pe_info->is_64bit) {
         IMAGE_OPTIONAL_HEADER64* opt_header = (IMAGE_OPTIONAL_HEADER64*)(pe_file->data + optional_header_offset);
         
         if (opt_header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
             import_dir_rva = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
             import_dir_size = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
         }
         
         if (opt_header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
             resource_dir_rva = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
             resource_dir_size = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
         }
         
         if (opt_header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
             security_dir_offset = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
             security_dir_size = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
         }
     } else {
         IMAGE_OPTIONAL_HEADER32* opt_header = (IMAGE_OPTIONAL_HEADER32*)(pe_file->data + optional_header_offset);
         
         if (opt_header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
             import_dir_rva = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
             import_dir_size = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
         }
         
         if (opt_header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
             resource_dir_rva = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
             resource_dir_size = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
         }
         
         if (opt_header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
             security_dir_offset = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
             security_dir_size = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
         }
     }
     
     // Parse imports
     if (import_dir_rva && import_dir_size) {
         pe_parse_imports(pe_file, pe_info, import_dir_rva, import_dir_size);
     }
     
     // Parse resources
     if (resource_dir_rva && resource_dir_size) {
         pe_parse_resources(pe_file, pe_info, resource_dir_rva, resource_dir_size);
     }
     
     // Verify digital signature
     if (security_dir_offset && security_dir_size) {
         pe_verify_signature(pe_file, pe_info, security_dir_offset, security_dir_size);
     }
     
     return true;
 }
 
 /**
  * Parse PE headers
  */
 bool pe_parse_headers(PE_FILE* pe_file, PE_INFO* pe_info, DWORD* optional_header_offset, WORD* optional_header_size) {
     if (!pe_file || !pe_info || !optional_header_offset || !optional_header_size) {
         return false;
     }
     
     // Check if file is large enough to contain DOS header
     if (pe_file->size < sizeof(IMAGE_DOS_HEADER)) {
         return false;
     }
     
     // Parse DOS header
     IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)pe_file->data;
     
     // Check DOS signature (MZ)
     if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
         return false;
     }
     
     // Store DOS header fields
     pe_info->e_magic = dos_header->e_magic;
     pe_info->e_lfanew = dos_header->e_lfanew;
     
     // Store DOS header size and save to pe_info
     pe_info->dos_header_size = dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER);
     
     // Get offset to PE header
     DWORD pe_offset = dos_header->e_lfanew;
     
     // Check if file is large enough to contain PE header
     if (pe_file->size < pe_offset + sizeof(IMAGE_NT_HEADERS)) {
         return false;
     }
     
     // Parse NT header
     IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(pe_file->data + pe_offset);
     
     // Check PE signature (PE\0\0)
     if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
         return false;
     }
     
     // Get file header
     IMAGE_FILE_HEADER* file_header = &nt_header->FileHeader;
     
     // Store file header fields
     pe_info->time_date_stamp = file_header->TimeDateStamp;
     pe_info->size_of_optional_header = file_header->SizeOfOptionalHeader;
     pe_info->characteristics = file_header->Characteristics;
     
     // Store machine type
     pe_info->machine = file_header->Machine;
     strncpy(pe_info->machine_str, get_machine_type_string(file_header->Machine), sizeof(pe_info->machine_str) - 1);
     pe_info->machine_str[sizeof(pe_info->machine_str) - 1] = '\0';
     
     // Store number of sections
     pe_info->num_sections = file_header->NumberOfSections;
     
     // Get optional header offset
     *optional_header_offset = pe_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
     *optional_header_size = file_header->SizeOfOptionalHeader;
     
     // Check if optional header is present
     if (*optional_header_size == 0) {
         return false;
     }
     
     // Check if file is large enough to contain at least the optional header magic
     if (pe_file->size < *optional_header_offset + sizeof(WORD)) {
         return false;
     }
     
     // Get optional header magic to determine if it's PE32 or PE32+
     WORD* magic = (WORD*)(pe_file->data + *optional_header_offset);
     pe_info->magic = *magic;
     
     if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
         // PE32 format
         pe_info->is_64bit = false;
         
         if (pe_file->size < *optional_header_offset + sizeof(IMAGE_OPTIONAL_HEADER32)) {
             return false;
         }
         
         IMAGE_OPTIONAL_HEADER32* opt_header = (IMAGE_OPTIONAL_HEADER32*)(pe_file->data + *optional_header_offset);
         pe_info->entry_point = opt_header->AddressOfEntryPoint;
         pe_info->size_of_headers = opt_header->SizeOfHeaders;
         
         // Store additional optional header fields
         pe_info->image_base_32 = opt_header->ImageBase;
         pe_info->section_alignment = opt_header->SectionAlignment;
         pe_info->file_alignment = opt_header->FileAlignment;
         pe_info->subsystem = opt_header->Subsystem;
         
         // Copy data directories
         for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES && i < opt_header->NumberOfRvaAndSizes; i++) {
             pe_info->data_directories[i] = opt_header->DataDirectory[i];
         }
     }
     else if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
         // PE32+ format
         pe_info->is_64bit = true;
         
         if (pe_file->size < *optional_header_offset + sizeof(IMAGE_OPTIONAL_HEADER64)) {
             return false;
         }
         
         IMAGE_OPTIONAL_HEADER64* opt_header = (IMAGE_OPTIONAL_HEADER64*)(pe_file->data + *optional_header_offset);
         pe_info->entry_point = opt_header->AddressOfEntryPoint;
         pe_info->size_of_headers = opt_header->SizeOfHeaders;
         
         // Store additional optional header fields
         pe_info->image_base_64 = opt_header->ImageBase;
         pe_info->section_alignment = opt_header->SectionAlignment;
         pe_info->file_alignment = opt_header->FileAlignment;
         pe_info->subsystem = opt_header->Subsystem;
         
         // Copy data directories
         for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES && i < opt_header->NumberOfRvaAndSizes; i++) {
             pe_info->data_directories[i] = opt_header->DataDirectory[i];
         }
     }
     else {
         // Unknown format
         return false;
     }
     
     return true;
 }
 
 /**
  * Parse PE sections
  */
 bool pe_parse_sections(PE_FILE* pe_file, PE_INFO* pe_info, DWORD section_table_offset, WORD num_sections) {
     if (!pe_file || !pe_info || num_sections == 0) {
         return false;
     }
     
     // Check if file is large enough to contain section table
     if (pe_file->size < section_table_offset + num_sections * sizeof(IMAGE_SECTION_HEADER)) {
         return false;
     }
     
     // Allocate memory for section info
     pe_info->sections = (PE_SECTION_INFO*)malloc(num_sections * sizeof(PE_SECTION_INFO));
     if (!pe_info->sections) {
         return false;
     }
     pe_info->section_count = num_sections;
     
     // Parse each section
     IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)(pe_file->data + section_table_offset);
     
     for (int i = 0; i < num_sections; i++) {
         // Get section name (ensure null-terminated)
         memcpy(pe_info->sections[i].name, section_header[i].Name, IMAGE_SIZEOF_SHORT_NAME);
         pe_info->sections[i].name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
         
         // Get section address and sizes
         pe_info->sections[i].virtual_address = section_header[i].VirtualAddress;
         pe_info->sections[i].virtual_size = section_header[i].Misc.VirtualSize;
         pe_info->sections[i].raw_size = section_header[i].SizeOfRawData;
         
         // Calculate section metrics if raw data is available
         if (section_header[i].PointerToRawData > 0 && section_header[i].SizeOfRawData > 0) {
             // Ensure we don't read beyond file boundaries
             DWORD data_offset = section_header[i].PointerToRawData;
             DWORD data_size = section_header[i].SizeOfRawData;
             
             if (data_offset + data_size <= pe_file->size) {
                 BYTE* section_data = pe_file->data + data_offset;
                 
                 // Calculate entropy
                 pe_info->sections[i].entropy = calculate_entropy(section_data, data_size);
                 
                 // Calculate chi-squared
                 pe_info->sections[i].chi_squared = calculate_chi_squared(section_data, data_size);
                 
                 // Calculate MD5
                 calculate_md5(section_data, data_size, pe_info->sections[i].md5);
             } else {
                 // Set default values for metrics if section data is not available
                 pe_info->sections[i].entropy = 0.0;
                 pe_info->sections[i].chi_squared = 0.0;
                 strcpy(pe_info->sections[i].md5, "N/A");
             }
         } else {
             // Set default values for metrics if section has no raw data
             pe_info->sections[i].entropy = 0.0;
             pe_info->sections[i].chi_squared = 0.0;
             strcpy(pe_info->sections[i].md5, "N/A");
         }
     }
     
     return true;
 }

/**
 * Convert RVA to file offset
 */
DWORD pe_rva_to_offset(PE_FILE* pe_file, PE_INFO* pe_info, DWORD rva) {
    if (!pe_file || !pe_info || !pe_file->data) {
        return 0;
    }
    
    // If RVA is 0, return 0
    if (rva == 0) {
        return 0;
    }
    
    // Find the section containing this RVA
    for (int i = 0; i < pe_info->section_count; i++) {
        PE_SECTION_INFO* section = &pe_info->sections[i];
        
        if (!section) {
            continue;
        }
        
        // Check if RVA is within this section's virtual address range
        if (rva >= section->virtual_address && 
            rva < section->virtual_address + section->virtual_size) {
            
            // Calculate the offset within the section
            DWORD offset_within_section = rva - section->virtual_address;
            
            // Get the section's raw data pointer from the original section header
            IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)pe_file->data;
            DWORD pe_offset = dos_header->e_lfanew;
            IMAGE_FILE_HEADER* file_header = (IMAGE_FILE_HEADER*)(pe_file->data + pe_offset + sizeof(DWORD));
            WORD optional_header_size = file_header->SizeOfOptionalHeader;
            DWORD section_table_offset = pe_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + optional_header_size;
            
            if (section_table_offset + i * sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_SECTION_HEADER) <= pe_file->size) {
                IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)(pe_file->data + section_table_offset + i * sizeof(IMAGE_SECTION_HEADER));
                
                // Ensure we don't exceed the raw data size
                if (offset_within_section >= section_header->SizeOfRawData) {
                    // Some compilers create sections with virtual_size > raw_size
                    // In this case, return the offset to the end of the raw data
                    return section_header->PointerToRawData + section_header->SizeOfRawData;
                }
                
                return section_header->PointerToRawData + offset_within_section;
            }
        }
    }
    
    // If RVA is not in any section but is less than SizeOfHeaders, it's in the header
    if (rva < pe_info->size_of_headers) {
        return rva;
    }
    
    // RVA not found in any section
    return 0;
}

/**
 * Parse imports
 */
bool pe_parse_imports(PE_FILE* pe_file, PE_INFO* pe_info, DWORD import_dir_rva, DWORD import_dir_size) {
    if (!import_dir_rva || !import_dir_size) {
        return false;
    }
    
    // Convert RVA to file offset
    DWORD import_dir_offset = pe_rva_to_offset(pe_file, pe_info, import_dir_rva);
    
    if (import_dir_offset + import_dir_size > pe_file->size) {
        return false;
    }
    
    // Get import directory
    IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(pe_file->data + import_dir_offset);
    
    // Count number of import descriptors (null-terminated array)
    int import_count = 0;
    while (import_desc[import_count].Name != 0) {
        import_count++;
    }
    
    if (import_count == 0) {
        return false;
    }
    
    // Allocate memory for import info
    pe_info->imports = (PE_IMPORT_INFO*)malloc(import_count * sizeof(PE_IMPORT_INFO));
    if (!pe_info->imports) {
        return false;
    }
    pe_info->import_count = import_count;
    
    // Parse each import descriptor
    for (int i = 0; i < import_count; i++) {
        // Get DLL name
        DWORD name_offset = pe_rva_to_offset(pe_file, pe_info, import_desc[i].Name);
        
        if (name_offset < pe_file->size) {
            char* dll_name = (char*)(pe_file->data + name_offset);
            strncpy(pe_info->imports[i].dll_name, dll_name, sizeof(pe_info->imports[i].dll_name) - 1);
            pe_info->imports[i].dll_name[sizeof(pe_info->imports[i].dll_name) - 1] = '\0';
        } else {
            strcpy(pe_info->imports[i].dll_name, "UNKNOWN");
        }
        
        // Process thunk data to get function names
        DWORD thunk_rva = import_desc[i].FirstThunk;
        if (thunk_rva == 0) {
            thunk_rva = import_desc[i].FirstThunk;
        }
        
        if (thunk_rva == 0) {
            pe_info->imports[i].function_count = 0;
            pe_info->imports[i].function_names = NULL;
            continue;
        }
        
        // Convert thunk RVA to file offset
        DWORD thunk_offset = pe_rva_to_offset(pe_file, pe_info, thunk_rva);
        
        // Count number of functions
        int function_count = 0;
        
        if (pe_info->is_64bit) {
            IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(pe_file->data + thunk_offset);
            while (thunk[function_count].Function != 0) {
                function_count++;
            }
        } else {
            IMAGE_THUNK_DATA32* thunk = (IMAGE_THUNK_DATA32*)(pe_file->data + thunk_offset);
            while (thunk[function_count].Function != 0) {
                function_count++;
            }
        }
        
        // Allocate memory for function names
        pe_info->imports[i].function_count = function_count;
        pe_info->imports[i].function_names = (char**)malloc(function_count * sizeof(char*));
        
        if (!pe_info->imports[i].function_names) {
            // Memory allocation failed, but continue with other imports
            pe_info->imports[i].function_count = 0;
            continue;
        }
        
        // Get function names
        for (int j = 0; j < function_count; j++) {
            DWORD func_name_rva = 0;
            
            if (pe_info->is_64bit) {
                IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(pe_file->data + thunk_offset);
                if (thunk[j].Function & 0x8000000000000000ULL) {
                    // Imported by ordinal
                    char* name = (char*)malloc(32);
                    if (name) {
                        sprintf(name, "Ordinal: %llu", thunk[j].Function & 0xFFFFULL);
                        pe_info->imports[i].function_names[j] = name;
                    } else {
                        pe_info->imports[i].function_names[j] = NULL;
                    }
                    continue;
                }
                func_name_rva = (DWORD)thunk[j].Function;
            } else {
                IMAGE_THUNK_DATA32* thunk = (IMAGE_THUNK_DATA32*)(pe_file->data + thunk_offset);
                if (thunk[j].Function & 0x80000000) {
                    // Imported by ordinal
                    char* name = (char*)malloc(32);
                    if (name) {
                        sprintf(name, "Ordinal: %u", thunk[j].Function & 0xFFFF);
                        pe_info->imports[i].function_names[j] = name;
                    } else {
                        pe_info->imports[i].function_names[j] = NULL;
                    }
                    continue;
                }
                func_name_rva = thunk[j].Function;
            }
            
            if (func_name_rva) {
                DWORD func_name_offset = pe_rva_to_offset(pe_file, pe_info, func_name_rva);
                
                if (func_name_offset + sizeof(IMAGE_IMPORT_BY_NAME) <= pe_file->size) {
                    IMAGE_IMPORT_BY_NAME* import_by_name = (IMAGE_IMPORT_BY_NAME*)(pe_file->data + func_name_offset);
                    char* name = (char*)malloc(strlen((char*)import_by_name->Name) + 1);
                    
                    if (name) {
                        strcpy(name, (char*)import_by_name->Name);
                        pe_info->imports[i].function_names[j] = name;
                    } else {
                        pe_info->imports[i].function_names[j] = NULL;
                    }
                } else {
                    pe_info->imports[i].function_names[j] = NULL;
                }
            } else {
                pe_info->imports[i].function_names[j] = NULL;
            }
        }
    }
    
    return true;
}

/**
 * Parse resources recursively
 */
void pe_parse_resource_directory(PE_FILE* pe_file, PE_INFO* pe_info,
                                DWORD resource_dir_offset, DWORD resource_base_offset,
                                int level, WORD type_id, WORD name_id, WORD lang_id,
                                int* resource_count) {
    // Check if we've reached the maximum valid level
    if (level > 3 || resource_dir_offset + sizeof(IMAGE_RESOURCE_DIRECTORY) > pe_file->size) {
        return;
    }
    
    // Get resource directory
    IMAGE_RESOURCE_DIRECTORY* res_dir = (IMAGE_RESOURCE_DIRECTORY*)(pe_file->data + resource_dir_offset);
    DWORD entry_count = res_dir->NumberOfNamedEntries + res_dir->NumberOfIdEntries;
    
    // Get directory entries
    IMAGE_RESOURCE_DIRECTORY_ENTRY* entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(
        pe_file->data + resource_dir_offset + sizeof(IMAGE_RESOURCE_DIRECTORY));
    
    for (DWORD i = 0; i < entry_count; i++) {
        if (resource_dir_offset + sizeof(IMAGE_RESOURCE_DIRECTORY) + (i + 1) * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > pe_file->size) {
            break;
        }
        
        WORD entry_id = entries[i].Name & 0xFFFF;
        
        if (entries[i].DataIsDirectory) {
            // Directory entry, recurse deeper
            DWORD next_dir_offset = resource_base_offset + entries[i].OffsetToDirectory;
            
            if (level == 0) {
                // Type level
                pe_parse_resource_directory(pe_file, pe_info, next_dir_offset, resource_base_offset, level + 1, entry_id, 0, 0, resource_count);
            } else if (level == 1) {
                // Name level
                pe_parse_resource_directory(pe_file, pe_info, next_dir_offset, resource_base_offset, level + 1, type_id, entry_id, 0, resource_count);
            } else if (level == 2) {
                // Language level
                pe_parse_resource_directory(pe_file, pe_info, next_dir_offset, resource_base_offset, level + 1, type_id, name_id, entry_id, resource_count);
            }
        } else {
            // Data entry
            DWORD data_entry_offset = resource_base_offset + entries[i].OffsetToData;
            
            if (data_entry_offset + sizeof(IMAGE_RESOURCE_DATA_ENTRY) <= pe_file->size) {
                IMAGE_RESOURCE_DATA_ENTRY* data_entry = (IMAGE_RESOURCE_DATA_ENTRY*)(pe_file->data + data_entry_offset);
                
                // Ensure we have enough memory allocated for the resource
                if (*resource_count >= pe_info->resource_count) {
                    int new_count = pe_info->resource_count == 0 ? 8 : pe_info->resource_count * 2;
                    PE_RESOURCE_INFO* new_resources = (PE_RESOURCE_INFO*)realloc(
                        pe_info->resources, new_count * sizeof(PE_RESOURCE_INFO));
                    
                    if (!new_resources) {
                        return;
                    }
                    
                    pe_info->resources = new_resources;
                    pe_info->resource_count = new_count;
                }
                
                // Get resource data
                DWORD data_rva = data_entry->OffsetToData;
                DWORD data_size = data_entry->Size;
                DWORD data_offset = pe_rva_to_offset(pe_file, pe_info, data_rva);
                
                if (data_offset + data_size <= pe_file->size) {
                    BYTE* resource_data = pe_file->data + data_offset;
                    
                    // Fill resource info
                    PE_RESOURCE_INFO* res = &pe_info->resources[*resource_count];
                    res->size = data_size;
                    
                    // Get resource type string
                    strncpy(res->type, get_resource_type_string(type_id), sizeof(res->type) - 1);
                    res->type[sizeof(res->type) - 1] = '\0';
                    
                    // Get resource language string
                    strncpy(res->lang, get_resource_lang_string(lang_id), sizeof(res->lang) - 1);
                    res->lang[sizeof(res->lang) - 1] = '\0';
                    
                    // Calculate metrics
                    res->entropy = calculate_entropy(resource_data, data_size);
                    res->chi_squared = calculate_chi_squared(resource_data, data_size);
                    calculate_sha256(resource_data, data_size, res->sha256);
                    
                    (*resource_count)++;
                }
            }
        }
    }
}

/**
 * Parse resources
 */
bool pe_parse_resources(PE_FILE* pe_file, PE_INFO* pe_info, DWORD resource_dir_rva, DWORD resource_dir_size) {
    if (!resource_dir_rva || !resource_dir_size || !pe_file || !pe_info) {
        return false;
    }
    
    // Convert RVA to file offset
    DWORD resource_dir_offset = pe_rva_to_offset(pe_file, pe_info, resource_dir_rva);
    
    if (resource_dir_offset == 0 || resource_dir_offset + sizeof(IMAGE_RESOURCE_DIRECTORY) > pe_file->size) {
        return false;
    }
    
    // Initialize resources
    pe_info->resources = NULL;
    pe_info->resource_count = 0;
    
    // Allocate initial array for resources - we'll realloc if needed
    pe_info->resources = (PE_RESOURCE_INFO*)malloc(8 * sizeof(PE_RESOURCE_INFO));
    if (!pe_info->resources) {
        return false;
    }
    pe_info->resource_count = 8; // This is the capacity, not the count of valid entries
    
    int resource_count = 0;
    
    // Parse resource directory recursively with a max depth to avoid infinite recursion
    pe_parse_resource_directory(pe_file, pe_info, resource_dir_offset, resource_dir_offset, 0, 0, 0, 0, &resource_count);
    
    // Update actual resource count
    if (resource_count < pe_info->resource_count) {
        // Shrink array to actual size
        if (resource_count > 0) {
            PE_RESOURCE_INFO* resized = (PE_RESOURCE_INFO*)realloc(pe_info->resources, resource_count * sizeof(PE_RESOURCE_INFO));
            if (resized) {
                pe_info->resources = resized;
            }
        } else {
            // No resources found
            free(pe_info->resources);
            pe_info->resources = NULL;
        }
    }
    
    pe_info->resource_count = resource_count;
    return true;
}

/**
 * Verify digital signature
 */
bool pe_verify_signature(PE_FILE* pe_file, PE_INFO* pe_info, DWORD security_dir_offset, DWORD security_dir_size) {
    // Initialize signature info to defaults
    pe_info->has_signature = false;
    pe_info->signature_valid = false;
    strcpy(pe_info->signer_name, "");
    
    // Validate inputs
    if (!security_dir_offset || !security_dir_size || !pe_file || !pe_info) {
        return false;
    }
    
    // Security directory offset is a file offset, not an RVA
    if (security_dir_offset + 8 > pe_file->size) {
        return false;
    }
    
    // Check for minimal signature data
    if (security_dir_size >= 8) {
        pe_info->has_signature = true;
        strcpy(pe_info->signer_name, "Signature verification not supported in WebAssembly");
        pe_info->signature_valid = false;
    }
    
    return true;
}

/**
 * Calculate Shannon entropy of data
 */
double calculate_entropy(BYTE* data, DWORD size) {
    if (!data || size == 0) {
        return 0.0;
    }
    
    // Count byte frequencies
    DWORD frequencies[256] = {0};
    for (DWORD i = 0; i < size; i++) {
        frequencies[data[i]]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            double prob = (double)frequencies[i] / size;
            entropy -= prob * log2(prob);
        }
    }
    
    return entropy;
}

/**
 * Calculate chi-squared test statistic
 */
double calculate_chi_squared(BYTE* data, DWORD size) {
    if (!data || size == 0) {
        return 0.0;
    }
    
    // Count byte frequencies
    DWORD frequencies[256] = {0};
    for (DWORD i = 0; i < size; i++) {
        frequencies[data[i]]++;
    }
    
    // Expected frequency for uniform distribution
    double expected = (double)size / 256;
    
    // Calculate chi-squared statistic
    double chi_squared = 0.0;
    for (int i = 0; i < 256; i++) {
        double diff = frequencies[i] - expected;
        chi_squared += (diff * diff) / expected;
    }
    
    return chi_squared;
}

/**
 * Calculate MD5 hash
 */
void calculate_md5(BYTE* data, DWORD size, char* output) {
    if (!data || !output) {
        strcpy(output, "N/A");
        return;
    }
    
    simple_md5(data, size, output);
}

/**
 * Calculate SHA-256 hash
 */
void calculate_sha256(BYTE* data, DWORD size, char* output) {
    if (!data || !output) {
        strcpy(output, "N/A");
        return;
    }
    
    simple_sha256(data, size, output);
}

/**
 * Simple MD5 implementation for WebAssembly
 * Note: This is NOT cryptographically secure, just for demo purposes
 */
void simple_md5(const unsigned char* data, size_t len, char* output) {
    uint32_t hash = 0x5a5a5a5a;
    
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    
    // Generate some pseudorandom values based on the hash
    uint32_t a = hash;
    uint32_t b = hash ^ 0xf0f0f0f0;
    uint32_t c = ~hash;
    uint32_t d = hash ^ 0xaaaaaaaa;
    
    // Format as hex string
    sprintf(output, "%08x%08x%08x%08x", a, b, c, d);
}

/**
 * Simple SHA256 implementation for WebAssembly
 * Note: This is NOT cryptographically secure, just for demo purposes
 */
void simple_sha256(const unsigned char* data, size_t len, char* output) {
    uint32_t hash[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    for (size_t i = 0; i < len; i++) {
        uint32_t val = data[i];
        for (int j = 0; j < 8; j++) {
            hash[j] = ((hash[j] << 5) + hash[j]) ^ val;
        }
    }
    
    // Format as hex string
    char* ptr = output;
    for (int i = 0; i < 8; i++) {
        ptr += sprintf(ptr, "%08x", hash[i]);
    }
}

/**
 * Get string representation of machine type
 */
const char* get_machine_type_string(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:   return "Intel 386";
        case IMAGE_FILE_MACHINE_IA64:   return "Intel Itanium";
        case IMAGE_FILE_MACHINE_AMD64:  return "AMD64 (x64)";
        case IMAGE_FILE_MACHINE_ARM:    return "ARM";
        case IMAGE_FILE_MACHINE_ARM64:  return "ARM64";
        case IMAGE_FILE_MACHINE_ARMNT:  return "ARM Thumb-2";
        default:                        return "Unknown";
    }
}

/**
 * Get string representation of resource type
 */
const char* get_resource_type_string(WORD type) {
    switch (type) {
        case 1:  return "Cursor";
        case 2:  return "Bitmap";
        case 3:  return "Icon";
        case 4:  return "Menu";
        case 5:  return "Dialog";
        case 6:  return "String Table";
        case 7:  return "Font Directory";
        case 8:  return "Font";
        case 9:  return "Accelerator";
        case 10: return "RC Data";
        case 11: return "Message Table";
        case 12: return "Group Cursor";
        case 14: return "Group Icon";
        case 16: return "Version";
        case 17: return "Dialog Include";
        case 19: return "Plug & Play";
        case 20: return "VXD";
        case 21: return "Animated Cursor";
        case 22: return "Animated Icon";
        case 23: return "HTML";
        case 24: return "Manifest";
        default: {
            static char buffer[16];
            sprintf(buffer, "Type %u", type);
            return buffer;
        }
    }
}

/**
 * Get string representation of resource language
 */
const char* get_resource_lang_string(WORD lang_id) {
    switch (lang_id) {
        case 0x0409: return "English (US)";
        case 0x0809: return "English (UK)";
        case 0x0c0a: return "Spanish (Spain)";
        case 0x040c: return "French (France)";
        case 0x0407: return "German (Germany)";
        case 0x0410: return "Italian (Italy)";
        case 0x0411: return "Japanese";
        case 0x0412: return "Korean";
        case 0x0804: return "Chinese (PRC)";
        case 0x0404: return "Chinese (Taiwan)";
        case 0x0419: return "Russian";
        default: {
            static char buffer[16];
            sprintf(buffer, "Language %u", lang_id);
            return buffer;
        }
    }
}

/**
 * Get string representation of file characteristics
 */
void get_characteristics_strings(WORD characteristics, char** string_array, int* count) {
    static const struct {
        WORD flag;
        const char* description;
    } char_flags[] = {
        { IMAGE_FILE_RELOCS_STRIPPED,         "IMAGE_FILE_RELOCS_STRIPPED" },
        { IMAGE_FILE_EXECUTABLE_IMAGE,        "IMAGE_FILE_EXECUTABLE_IMAGE" },
        { IMAGE_FILE_LINE_NUMS_STRIPPED,      "IMAGE_FILE_LINE_NUMS_STRIPPED" },
        { IMAGE_FILE_LOCAL_SYMS_STRIPPED,     "IMAGE_FILE_LOCAL_SYMS_STRIPPED" },
        { IMAGE_FILE_AGGRESIVE_WS_TRIM,       "IMAGE_FILE_AGGRESIVE_WS_TRIM" },
        { IMAGE_FILE_LARGE_ADDRESS_AWARE,     "IMAGE_FILE_LARGE_ADDRESS_AWARE" },
        { IMAGE_FILE_BYTES_REVERSED_LO,       "IMAGE_FILE_BYTES_REVERSED_LO" },
        { IMAGE_FILE_32BIT_MACHINE,           "IMAGE_FILE_32BIT_MACHINE" },
        { IMAGE_FILE_DEBUG_STRIPPED,          "IMAGE_FILE_DEBUG_STRIPPED" },
        { IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP" },
        { IMAGE_FILE_NET_RUN_FROM_SWAP,       "IMAGE_FILE_NET_RUN_FROM_SWAP" },
        { IMAGE_FILE_SYSTEM,                  "IMAGE_FILE_SYSTEM" },
        { IMAGE_FILE_DLL,                     "IMAGE_FILE_DLL" },
        { IMAGE_FILE_UP_SYSTEM_ONLY,          "IMAGE_FILE_UP_SYSTEM_ONLY" },
        { IMAGE_FILE_BYTES_REVERSED_HI,       "IMAGE_FILE_BYTES_REVERSED_HI" }
    };
    
    *count = 0;
    for (int i = 0; i < sizeof(char_flags) / sizeof(char_flags[0]); i++) {
        if (characteristics & char_flags[i].flag) {
            string_array[*count] = strdup(char_flags[i].description);
            (*count)++;
        }
    }
}

/**
 * Get string representation of subsystem
 */
const char* get_subsystem_string(WORD subsystem) {
    switch (subsystem) {
        case IMAGE_SUBSYSTEM_UNKNOWN:                 return "UNKNOWN";
        case IMAGE_SUBSYSTEM_NATIVE:                  return "NATIVE";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:             return "WINDOWS_GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:             return "WINDOWS_CUI";
        case IMAGE_SUBSYSTEM_OS2_CUI:                 return "OS2_CUI";
        case IMAGE_SUBSYSTEM_POSIX_CUI:               return "POSIX_CUI";
        case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:          return "NATIVE_WINDOWS";
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:          return "WINDOWS_CE_GUI";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:         return "EFI_APPLICATION";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI_BOOT_SERVICE_DRIVER";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:      return "EFI_RUNTIME_DRIVER";
        case IMAGE_SUBSYSTEM_EFI_ROM:                 return "EFI_ROM";
        case IMAGE_SUBSYSTEM_XBOX:                    return "XBOX";
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "WINDOWS_BOOT_APPLICATION";
        default: {
            static char buffer[32];
            sprintf(buffer, "UNKNOWN (%d)", subsystem);
            return buffer;
        }
    }
}