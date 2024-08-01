// Written by 0xfa11
// 29-07-2024

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <assert.h>
#include <errno.h>

#define EI_NIDENT (16)

int fill_headers64(Elf64_Ehdr *headers, const char *filename);
int get_pht_entries64(Elf64_Phdr ***entries, Elf64_Ehdr *headers, char *filename);
int get_sht_entries64(Elf64_Shdr ***entries, Elf64_Ehdr *headers, char *filename);
int get_sht_dynsym_index(Elf64_Shdr **entries, int n);
int loader64(Elf64_Phdr **p_entries, Elf64_Shdr **s_entries, Elf64_Ehdr *headers, char *filename);
int arch_identify(char *filename);
int valid_elf(FILE *file);
int main64(char *filename);
int file_exists (char *filename);
void relocate(Elf64_Shdr *shdr, Elf64_Sym *syms, char *strings, FILE *file, void *allocated_mem);
void *resolve_sym(const char* sym);
int find_symbol_table(Elf64_Ehdr *headers, Elf64_Shdr **s_entries);
void* find_sym(const char *sym_name, Elf64_Shdr **s_entries, Elf64_Shdr *symtab, FILE *file, void *allocated_mem);

int BIN_ARCHITECTURE = 0;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s [filename]\n", argv[0]);
        return 1;
    }
    
    char *filename = argv[1];
    
    if (!file_exists(filename)) {
        fprintf(stderr, "[x] File does not exist\n");
        return 1;
    }

    int arch = arch_identify(filename);
    if (arch == 1) {
        fprintf(stderr, "[x] Could not identify architecture\n");
        return 1;
    }
    
    BIN_ARCHITECTURE = -arch;
    
    if (BIN_ARCHITECTURE == 1) {
        fprintf(stderr, "[x] Expected 32 bit ELF file. Exiting");
        return 1;
    }
    else if (BIN_ARCHITECTURE == 2) {
        main64(filename);
    }

    return 0;
}

int main64(char *filename) {
    int flag = 0;
    Elf64_Ehdr headers = {0};
    if(fill_headers64(&headers, filename)) {
        fprintf(stderr, "[x] fill_headers32 Failed.\n");
        return 1;
    }

    Elf64_Phdr **p_entries = NULL;
    Elf64_Shdr **s_entries = NULL;

    if (get_pht_entries64(&p_entries, &headers, filename)) {
        fprintf(stderr, "[x] get_pht_entries32 Failed\n");
        return 1;
    }

    if (get_sht_entries64(&s_entries, &headers, filename)) {
        fprintf(stderr, "[x] get_sht_entries32 Failed\n");
        return 1;
    }


    if(loader64(p_entries, s_entries, &headers, filename)) {
        fprintf(stderr, "[x] Failed to load and execute ELF File\n");
        flag = 1;
    }

    for (int i = 0; i < headers.e_phnum; ++i) {
       free(p_entries[i]);
    }
    free(p_entries);

    for (int i = 0; i < headers.e_shnum; ++i) {
       free(s_entries[i]);
    }
    free(s_entries);


    return flag;
} 

int fill_headers64(Elf64_Ehdr *headers, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[x] Error: Unable to open file\n");
        return 1;
    }

    if (valid_elf(file)) {
        fprintf(stderr, "[x] Error: Not an ELF or corrupted file.\n");
        return 1;
    }


    // Read the ELF header
    size_t bytesRead = fread(headers, 1, sizeof(Elf64_Ehdr), file);
    if (bytesRead != sizeof(Elf64_Ehdr)) {
        if (feof(file)) {
            fprintf(stderr, "[x] Error: Unexpected end of file while reading ELF header\n");
        } else if (ferror(file)) {
            perror("[x] Error reading file");
        }
        fclose(file);
        return 1;
    }
    
    // Close the file
    fclose(file);
    return 0;
}

//Returns -1 if 32bit, -2 if 64 bit.
int arch_identify(char *filename) {

    FILE *file = fopen(filename, "rb");

    if (valid_elf(file)) {
        fprintf(stderr, "[x] Error: Not an ELF or corrupted file.\n");
        return 1;
    }
    char arch;

    if (fseek(file, 0x4, SEEK_SET) != 0) {
        perror("Error seeking to offset");
        fclose(file);
        return 1;
    }

    // Read a single byte from the file at the current position
    if (fread(&arch, sizeof(arch), 1, file) != 1) {
        perror("Error reading byte");
        fclose(file);
        return 1;
    }

    if (arch == 0x1)
        return -1;

    return -2;
}


//Validates ELF file by checking magic bytes, Will set the given file to 0x0.
int valid_elf(FILE *file) {

    if (fseek(file, 0x0, SEEK_SET) != 0) {
        perror("Error seeking to offset");
        fclose(file);
        return EXIT_FAILURE;
    }

    char magic_bytes[4];

    if (fread(&magic_bytes, sizeof(magic_bytes), 1, file) != 1) {
        perror("Error reading byte");
        fclose(file);
        return EXIT_FAILURE;
    }

    if (fseek(file, 0x0, SEEK_SET) != 0) {
        perror("Error seeking to offset");
        fclose(file);
        return EXIT_FAILURE;
    }

    return !(magic_bytes[0] == 0x7f && magic_bytes[1] == 'E' && magic_bytes[2] == 'L' && magic_bytes[3] == 'F');
}

//Allocates memory for array of Program header table entries
//make sure to free after using.

int get_pht_entries64(Elf64_Phdr ***entries, Elf64_Ehdr *headers, char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[x] Failed to open file\n");
        return 1;
    }

    if (valid_elf(file)) {
        fprintf(stderr, "[x] Error: Not an ELF or corrupted file.\n");
        fclose(file);
        return 1;
    }

    // Allocate memory for array of pointers to Elf64_Phdr
    *entries = malloc(headers->e_phnum * sizeof(Elf64_Phdr *));
    if (!*entries) {
        fprintf(stderr, "[x] Error: Failed to allocate memory for entries in get_pht_entries32\n");
        fclose(file);
        return 1;
    }

    // Allocate memory for each program header entry
    for (int i = 0; i < headers->e_phnum; ++i) {
        (*entries)[i] = malloc(headers->e_phentsize);
        if (!(*entries)[i]) {
            fprintf(stderr, "[x] Error: Failed to allocate memory for entry[%d] in get_pht_entries32\n", i);
            // Free previously allocated memory
            for (int j = 0; j < i; ++j) {
                free((*entries)[j]);
            }
            free(*entries);
            fclose(file);
            return 1;
        }
    }

    // Seek to the start of the program header table
    if (fseek(file, headers->e_phoff, SEEK_SET) != 0) {
        perror("Error seeking to offset");
        for (int i = 0; i < headers->e_phnum; ++i) {
            free((*entries)[i]);
        }
        free(*entries);
        fclose(file);
        return 1;
    }

    // Read the program header table entries
    for (int i = 0; i < headers->e_phnum; ++i) {
        if (fread((*entries)[i], headers->e_phentsize, 1, file) != 1) {
            perror("Error reading byte");
            for (int j = 0; j < headers->e_phnum; ++j) {
                free((*entries)[j]);
            }
            free(*entries);
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

int get_sht_entries64(Elf64_Shdr ***entries, Elf64_Ehdr *headers, char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[x] Failed to open file\n");
        return 1;
    }

    if (valid_elf(file)) {
        fprintf(stderr, "[x] Error: Not an ELF or corrupted file.\n");
        fclose(file);
        return 1;
    }

    // Allocate memory for array of pointers to Elf64_Phdr
    *entries = malloc(headers->e_shnum * sizeof(Elf64_Shdr *));
    if (!*entries) {
        fprintf(stderr, "[x] Error: Failed to allocate memory for entries in get_sht_entries32\n");
        fclose(file);
        return 1;
    }

    // Allocate memory for each program header entry
    for (int i = 0; i < headers->e_shnum; ++i) {
        (*entries)[i] = malloc(headers->e_shentsize);
        if (!(*entries)[i]) {
            fprintf(stderr, "[x] Error: Failed to allocate memory for entry[%d] in get_sht_entries32\n", i);
            // Free previously allocated memory
            for (int j = 0; j < i; ++j) {
                free((*entries)[j]);
            }
            free(*entries);
            fclose(file);
            return 1;
        }
    }

    // Seek to the start of the program header table
    if (fseek(file, headers->e_shoff, SEEK_SET) != 0) {
        perror("Error seeking to offset");
        for (int i = 0; i < headers->e_shnum; ++i) {
            free((*entries)[i]);
        }
        free(*entries);
        fclose(file);
        return 1;
    }

    // Read the program header table entries
    for (int i = 0; i < headers->e_shnum; ++i) {
        if (fread((*entries)[i], headers->e_shentsize, 1, file) != 1) {
            perror("Error reading byte");
            for (int j = 0; j < headers->e_shnum; ++j) {
                free((*entries)[j]);
            }
            free(*entries);
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

int get_sht_dynsym_index(Elf64_Shdr **entries, int n) {
    for (int i = 0; i < n; ++i) {
        if (entries[i]->sh_type == SHT_DYNSYM) {
            return i;
        }
    }

    return -1;
}


int loader64(Elf64_Phdr **p_entries, Elf64_Shdr **s_entries, Elf64_Ehdr *headers, char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[x] Failed to open file: %s\n", strerror(errno));
        return 1;
    }

    // Calculate the size needed to map all segments
    Elf64_Addr max_addr = 0;
    for (int i = 0; i < headers->e_phnum; ++i) {
        if (p_entries[i]->p_type == PT_LOAD) {
            Elf64_Addr end_addr = p_entries[i]->p_vaddr + p_entries[i]->p_memsz;
            if (end_addr > max_addr) {
                max_addr = end_addr;
            }
        }
    }

    // Align max_addr to page size (usually 4096 bytes)
    max_addr = (max_addr + 0xFFF) & ~0xFFF;

    void *allocated_mem = mmap(NULL, max_addr, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (allocated_mem == MAP_FAILED) {
        perror("[x] mmap Failed");
        fclose(file);
        return 1;
    }

    // Zero out memory
    memset(allocated_mem, 0x0, max_addr);

    for (int i = 0; i < headers->e_phnum; ++i) {
        if (p_entries[i]->p_type == PT_LOAD) {
            if (p_entries[i]->p_filesz > p_entries[i]->p_memsz) {
                fprintf(stderr, "[x] p_filesz is greater than p_memsz\n");
                munmap(allocated_mem, max_addr);
                fclose(file);
                return 1;
            }

            fseek(file, p_entries[i]->p_offset, SEEK_SET);
            unsigned char *section_start = (unsigned char *)allocated_mem + p_entries[i]->p_vaddr;
            fread(section_start, 1, p_entries[i]->p_filesz, file);


            int prot = PROT_READ;
            if (p_entries[i]->p_flags & PF_W) prot |= PROT_WRITE;
            if (p_entries[i]->p_flags & PF_X) prot |= PROT_EXEC;
            mprotect(section_start, p_entries[i]->p_memsz, prot);
        }
    }

    //Get Global Symbol Table
    // Get Global Symbol Table
    int sht_dynsym_index = get_sht_dynsym_index(s_entries, headers->e_shnum);
    if (sht_dynsym_index != -1) {
        // Allocate memory for the symbol table
        Elf64_Sym *global_symbol_table = malloc(s_entries[sht_dynsym_index]->sh_size);
        if (!global_symbol_table) {
            fprintf(stderr, "[x] Error: Failed to allocate memory for global symbol table\n");
            munmap(allocated_mem, max_addr);
            fclose(file);
            return 1;
        }

        fseek(file, s_entries[sht_dynsym_index]->sh_offset, SEEK_SET);
        fread(global_symbol_table, s_entries[sht_dynsym_index]->sh_size, 1, file);

        // Get Associated Global String Table
        fseek(file, s_entries[s_entries[sht_dynsym_index]->sh_link]->sh_offset, SEEK_SET);
        char *global_strings = malloc(s_entries[s_entries[sht_dynsym_index]->sh_link]->sh_size);
        if (!global_strings) {
            fprintf(stderr, "[x] Error: Failed to allocate memory for global strings\n");
            free(global_symbol_table);
            munmap(allocated_mem, max_addr);
            fclose(file);
            return 1;
        }
        fread(global_strings, s_entries[s_entries[sht_dynsym_index]->sh_link]->sh_size, 1, file);

        // Relocate each relocatable SHT
        for (int i = 0; i < headers->e_shnum; ++i) {
            if (s_entries[i]->sh_type == SHT_REL) {
                relocate(s_entries[i], global_symbol_table, global_strings, file, allocated_mem);
            }
        }

        free(global_strings);
        free(global_symbol_table);
    } else {
        fprintf(stdout, "[x] get_sht_dynsym_index did not find global symbol table index\n");
    }

    // Find the main function in the symbol table
    int symbol_table_index = find_symbol_table(headers, s_entries);
    void *entry = find_sym("main", s_entries, s_entries[symbol_table_index], file, allocated_mem);

    int (*main_func)(int, char **) = (int (*)(int, char **))entry;
    main_func(1, NULL);

    fclose(file);
    munmap(allocated_mem, max_addr);

    return 0;
}

void relocate(Elf64_Shdr *shdr, Elf64_Sym *syms, char *strings, FILE *file, void *allocated_mem) {
    // Allocate memory for the relocation entries
    Elf64_Rel *rel = malloc(shdr->sh_size);
    if (!rel) {
        fprintf(stderr, "[x] Error: Failed to allocate memory for relocation entries\n");
        return;
    }

    // Seek to the start of the relocation entries
    fseek(file, shdr->sh_offset, SEEK_SET);

    // Read all the relocation entries
    size_t entries_read = fread(rel, 1, shdr->sh_size, file);
    if (entries_read != shdr->sh_size) {
        fprintf(stderr, "[x] Error: Failed to read relocation entries\n");
        free(rel);
        return;
    }

    // Perform relocation
    for (int j = 0; j < shdr->sh_size / sizeof(Elf64_Rel); j++) {
        const char *sym = strings + syms[ELF32_R_SYM(rel[j].r_info)].st_name;
        
        switch (ELF32_R_TYPE(rel[j].r_info)) {
            case R_386_JMP_SLOT:
            case R_386_GLOB_DAT:
                *(Elf64_Word *)(allocated_mem + rel[j].r_offset) = (Elf64_Word)(uintptr_t)resolve_sym(sym);
                break;
        }
    }

    // Free the allocated memory for relocation entries
    free(rel);
}


void* resolve_sym(const char* sym) {
    static void *handle = NULL;

    if (handle == NULL)
    {
        handle = dlopen("libc.so.6", RTLD_NOW);
    }

    assert(handle != NULL);

    void* resolved_sym = dlsym(handle, sym);

    // assert(resolved_sym != NULL);

    return resolved_sym;
}

int find_symbol_table(Elf64_Ehdr *headers, Elf64_Shdr **s_entries) {
    for (int i = 0; i < headers->e_shnum; ++i) {
        if (s_entries[i]->sh_type == SHT_SYMTAB) {
            return i;
        }
    }
    return -1; // Symbol table not found
}

void* find_sym(const char *sym_name, Elf64_Shdr **s_entries, Elf64_Shdr *symtab, FILE *file, void *allocated_mem) {
    // Allocate memory for the symbol table
    Elf64_Sym *sym_table = malloc(symtab->sh_size);
    if (!sym_table) {
        fprintf(stderr, "[x] Error: Failed to allocate memory for symbol table\n");
        return NULL;
    }

    // Read the symbol table from the file
    fseek(file, symtab->sh_offset, SEEK_SET);
    fread(sym_table, symtab->sh_size, 1, file);

    // Get the associated string table
    Elf64_Shdr *strtab = s_entries[symtab->sh_link];
    fseek(file, strtab->sh_offset, SEEK_SET);
    char *str_table = malloc(strtab->sh_size);
    if (!str_table) {
        fprintf(stderr, "[x] Error: Failed to allocate memory for string table\n");
        free(sym_table);
        return NULL;
    }
    fread(str_table, strtab->sh_size, 1, file);

    // Iterate over the symbol table to find the symbol
    for (int i = 0; i < symtab->sh_size / sizeof(Elf64_Sym); ++i) {
        if (strcmp(&str_table[sym_table[i].st_name], sym_name) == 0) {
            void *sym_addr = (void *)((uintptr_t)allocated_mem + sym_table[i].st_value);
            free(sym_table);
            free(str_table);
            return sym_addr;
        }
    }

    // Symbol not found
    fprintf(stderr, "[x] Error: Symbol %s not found\n", sym_name);
    free(sym_table);
    free(str_table);
    return NULL;
}


int file_exists (char *filename) {
  struct stat   buffer;   
  return (stat (filename, &buffer) == 0);
}

