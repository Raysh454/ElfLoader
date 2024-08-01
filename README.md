# ElfLoader

A simple ELFLoader I wrote to learn about the ELF Structure

# ELF
Elf is the file format used for .o object files, binaries, shared libraries and core dumps in Linux.

Elf Files are used  by two tools, the linker and the loader. A linker combines multiple ELF files into an executable or a library and a loader loads the executable ELF file in the memory of the process.

# Linker
The linker needs to know where the DATA, TEXT, BSS, and other sections are to merge them with sections from other libraries. If relocation is required the linker needs to know where the symbol tables and relocation information is.

# Loader
On the other hand, the loader does not need any of these details. It simply needs to know which parts of the ELF file are code (executable), which are data and read-only data, and where to put the BSS in the memory of a process.

# Elf Structure
So the ELF file provides two separate views on the data inside the ELF. A linker view with several details and a loader view, a higher level view with fewer details.

* Section Header Table: With pointers to sections to be used by the linker.
* Program Header Table: With pointers to segments to be used by the loader.

Parts of the ELF file used by the linker are called "Sections", and the parts used by the loader are called "segments"

Neither the SHT nor the PHT have fixed positions, they can be located anywhere in an ELF file. To find them the ELF header is used, which is located at the very start of the file.

The first bytes contain the elf magic `"\x7fELF"`, followed by the class ID (32 or 64 bit ELF file), the data format ID (little endian/big endian), the machine type, etc.

At the end of the ELF header are then pointers to the SHT and PHT. Specifically, the Segment Header Table which is used by the linker starts at byte 1120 in the ELF file, and the Program Header Table starts at byte 52 (right after the ELF header)


# Steps to load a simple ELF

* Parse the ELF header
* Test for compatibility
* Get the Program Header Offset
* Get all entries from Program Header
* Allocate space in memory
* Load all PHT entries with type PT_LOAD
* Get all SHT entries
* Get Symbols and Strings required for Dynamic Linking from SHT with type SHT_DYNSYM
* Relocate all the necessary sections to Reserved memory.
* Get the Symbol Table from SHT with type SHT_SYMTAB
* Locate the main function
* Transfer Control

Note :- The ElfLoader64 Throws a Segfault when jumping to the loaded program too lazy to debug.
