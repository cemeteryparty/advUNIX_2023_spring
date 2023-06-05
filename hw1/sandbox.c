#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <elf.h>
#include "elf-parser.h"

int log_fd;
char cfg_path[128], logStr[512];
char str[256], c;
FILE *cfg_fd;

// __libc_start_main_OLD: function pointer of original entry
int (*__libc_start_main_OLD)(
    int *(int, char **, char **),
    int , char **, void (*)(void),
    void (*)(void), void (*)(void), void (*)) = NULL;
int (*open_OLD)(const char *, int, ...) = NULL;
ssize_t (*read_OLD)(int, void *, size_t) = NULL;
ssize_t (*write_OLD)(int, const void *, size_t) = NULL;
int (*connect_OLD)(int, const struct sockaddr *, socklen_t) = NULL;
int (*getaddrinfo_OLD)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
int (*system_OLD)(const char *command) = NULL;

int open_NEW(const char *pathname, int flags, ...) {
    // printf("\t---  secure open  ---\t\n");
    int ret = -1, i = 0, ini_list = 0;
    memset(logStr, 0, 512);
    memset(str, 0, 256);
    char abspath[128];
    realpath(pathname, abspath);

    mode_t mode = 0;
    va_list args;
    va_start(args, flags);
    if (flags & O_CREAT) { mode = va_arg(args, mode_t); }
    
    fseek(cfg_fd, 0, SEEK_SET);
    while ((c = fgetc(cfg_fd)) != EOF) {
        if (c == '\n') {
            if (!strcmp(str, "BEGIN open-blacklist")) { ini_list = 1; }
            else if (!strcmp(str, "END open-blacklist")) { break; }
            else if (ini_list) {
                if (!strcmp(abspath, str)) { errno = EACCES; ret = ini_list = -1; }
            }
            i = 0; memset(str, 0, 256);
        }
        else { str[i++] = c; }
    }
    if (ini_list > 0) { ret = open_OLD(pathname, flags, mode); }

    sprintf(logStr, "[logger] open(\"%s\", %d, %d) = %d\n", pathname, flags, mode, ret);
    write_OLD(log_fd, logStr, strlen(logStr));
    return ret;
}

ssize_t read_NEW(int fd, void *buf, size_t count) {
    // printf("\t---  secure read  ---\t\n");
    int ret = 0, i = 0, ini_list = 0, lret = 0;
    memset(logStr, 0, 512);
    memset(str, 0, 256);
    
    char logpath[64]; pid_t pid = getpid();
    sprintf(logpath, "%d-%d-read.log", pid, fd);

    char *ban_pattern = str, *query = (char *)malloc(count + 1024);
    memset(query, 0, count + 1024);
    fseek(cfg_fd, 0, SEEK_SET);
    while ((c = fgetc(cfg_fd)) != EOF) {
        if (c == '\n') {
            if (!strcmp(str, "BEGIN read-blacklist")) { ini_list = 1; }
            else if (!strcmp(str, "END read-blacklist")) { break; }
            else if (ini_list) {
                int rd_fd = open_OLD(logpath, O_RDONLY);
                if (rd_fd >= 0) {
                    lret = lseek(rd_fd, -strlen(ban_pattern), SEEK_END);
                    if (lret < 0) { lret = lseek(rd_fd, 0, SEEK_SET); }
                    lret = read_OLD(rd_fd, query, strlen(ban_pattern));
                }
                close(rd_fd);
                ret = read_OLD(fd, (query + lret), count);

                if (strstr(query, ban_pattern) != NULL) {
                    close(fd);
                    errno = EIO; ret = ini_list = -1;
                    break;
                }
            }
            i = 0; memset(str, 0, 256);
        }
        else { str[i++] = c; }
    }

    int wrt_fd = open_OLD(logpath, O_CREAT | O_APPEND | O_WRONLY, 0644);
    if (ini_list > 0) {
        memcpy(buf, (query + lret), ret);
        write_OLD(wrt_fd, buf, ret);
    }
    close(wrt_fd);

    sprintf(logStr, "[logger] read(%d, %p, %ld) = %d\n", fd, buf, count, ret);
    write_OLD(log_fd, logStr, strlen(logStr));
    free(query);
    return ret;
}

ssize_t write_NEW(int fd, const void *buf, size_t count) {
    // printf("\t---  secure write  ---\t\n");
    char logpath[64]; pid_t pid = getpid();

    sprintf(logpath, "%d-%d-write.log", pid, fd);
    int wrt_fd = open_OLD(logpath, O_CREAT | O_APPEND | O_WRONLY, 0644);
    write_OLD(wrt_fd, buf, count);
    close(wrt_fd);

    ssize_t ret = write_OLD(fd, buf, count);
    sprintf(logStr, "[logger] write(%d, %p, %ld) = %ld\n", fd, buf, count, ret);
    write_OLD(log_fd, logStr, strlen(logStr));
    return ret;
}

int connect_NEW(int socket, const struct sockaddr *address, socklen_t address_len) {
    // printf("\t---  secure connect  ---\t\n");
    int ret = -1, ini_list = 0, i = 0, slen;
    memset(logStr, 0, 512);
    memset(str, 0, 256);

    struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
    struct sockaddr_in *addr_ban;
    char ip[20], port[10];
    slen = strlen(inet_ntoa(addr_in->sin_addr));
    memcpy(ip, inet_ntoa(addr_in->sin_addr), slen); 
    ip[slen] = '\0';
    sprintf(port, "%d", htons(addr_in->sin_port));
    // printf("[GET REQUEST] %s:%s\n", ip, port);

    char *ban_domain = str, ban_ip[20], ban_port[10];
    memset(ban_domain, 0, strlen(ban_domain));
    memset(ban_port, 0, 10);
    memset(ban_ip, 0, 20);
    
    char *entry = ban_domain;
    fseek(cfg_fd, 0, SEEK_SET);
    // FILE *cfg_fd = fopen(cfg_path, "r");
    while ((c = fgetc(cfg_fd)) != EOF) {
        if (c == '\n') {
            if (!strcmp(str, "BEGIN connect-blacklist")) { ini_list = 1; }
            else if (!strcmp(str, "END connect-blacklist")) { break; }
            else if (ini_list > 0) {
                // printf("[BLOCK] %s:%s\n", ban_domain, ban_port);
                struct addrinfo hints, *res, *addr_p;
                memset(&hints, 0, sizeof(struct addrinfo));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_flags = AI_PASSIVE;
                int chk = getaddrinfo_OLD(ban_domain, NULL, &hints, &res);
                if (chk != 0) { perror("getaddrinfo(ban_domain)"); return -1; }
                for (addr_p = res; addr_p != NULL; addr_p = addr_p->ai_next) {
                    addr_ban = (struct sockaddr_in *)addr_p->ai_addr;
                    slen = strlen(inet_ntoa(addr_ban->sin_addr));
                    memcpy(ban_ip, inet_ntoa(addr_ban->sin_addr), slen);
                    ban_ip[slen] = '\0';
                    // printf("[BAN] %s:%s [QUERY] %s:%s\n", ban_ip, ban_port, ip, port);
                    if (!strcmp(ip, ban_ip) && !strcmp(port, ban_port)) {
                        errno = ECONNREFUSED;
                        ini_list = ret = -1;
                        break;
                    }
                }
            }
            memset(ban_domain, 0, strlen(ban_domain));
            memset(ban_port, 0, 10);
            memset(ban_ip, 0, 20);
            entry = ban_domain; i = 0; 
        }
        else {
            if (c == ':') { i = 0; entry = ban_port; }
            else { entry[i++] = c; }
        }
    }
    // fclose(cfg_fd);
    if (ini_list > 0) { ret = connect_OLD(socket, address, address_len); }

    sprintf(logStr, "[logger] connect(%d, \"%s\", %d) = %d\n", socket, ip, address_len, ret);
    write_OLD(log_fd, logStr, strlen(logStr));
    return ret;
}

int getaddrinfo_NEW(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    // printf("\t---  secure getaddrinfo  ---\t\n");
    int ret = -1, ini_list = 0, i = 0;
    memset(logStr, 0, 512);
    memset(str, 0, 256);

    fseek(cfg_fd, 0, SEEK_SET);
    while ((c = fgetc(cfg_fd)) != EOF) {
        if (c == '\n') {
            if (!strcmp(str, "BEGIN getaddrinfo-blacklist")) { ini_list = 1; }
            else if (!strcmp(str, "END getaddrinfo-blacklist")) { break; }
            else if (ini_list > 0) {
                if (!strcmp(node, str)) { ret = EAI_NONAME; ini_list = -1; }
            }
            i = 0; memset(str, 0, strlen(str));
        }
        else { str[i++] = c; }
    }
    if (ini_list > 0) { ret = getaddrinfo_OLD(node, service, hints, res); }

    sprintf(logStr, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, ret);
    write_OLD(log_fd, logStr, strlen(logStr));
    return ret;
}

int system_NEW(const char *command) {
    // printf("\t---  secure system  ---\t\n");
    sprintf(logStr, "[logger] system(\"%s\")\n", command);
    write_OLD(log_fd, logStr, strlen(logStr));
    return system_OLD(command);
}

void collect_6_offset(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[], uint64_t *offsets) {
    // https://github.com/TheCodeArtist/elf-parser/blob/master/elf-parser.c
    // https://stackoverflow.com/questions/45319775/how-can-i-get-the-symbol-name-in-struct-elf64-rela
    uint32_t i, str_tbl_ndx;
    char *sh_str;

    int rel_symbol_count;
    Elf64_Rela* rel_tbl;

    char *str_tbl; // base str address of symbol table
    Elf64_Sym* sym_tbl;
    
    sh_str = read_section64(fd, sh_table[eh.e_shstrndx]);
    for (i = 0; i < eh.e_shnum; i++) {
        if (!strcmp((sh_str + sh_table[i].sh_name), ".rela.plt")) {
            rel_tbl = (Elf64_Rela*)read_section64(fd, sh_table[i]);
            rel_symbol_count = (sh_table[i].sh_size / sizeof(Elf64_Rela));
        }

        if (!strcmp((sh_str + sh_table[i].sh_name), ".dynsym")) {
            sym_tbl = (Elf64_Sym*)read_section64(fd, sh_table[i]);
            str_tbl_ndx = sh_table[i].sh_link;
            str_tbl = read_section64(fd, sh_table[str_tbl_ndx]);
        }
    }
    

    for (i = 0; i < rel_symbol_count; i++) {
        if (!strcmp((str_tbl + sym_tbl[ELF64_R_SYM(rel_tbl[i].r_info)].st_name), "open")) {
            offsets[0] = rel_tbl[i].r_offset;
            // printf("open: %016lx\n", rel_tbl[i].r_offset);
        }
        if (!strcmp((str_tbl + sym_tbl[ELF64_R_SYM(rel_tbl[i].r_info)].st_name), "read")) {
            offsets[1] = rel_tbl[i].r_offset;
            // printf("read: %016lx\n", rel_tbl[i].r_offset);
        }
        if (!strcmp((str_tbl + sym_tbl[ELF64_R_SYM(rel_tbl[i].r_info)].st_name), "write")) {
            offsets[2] = rel_tbl[i].r_offset;
            // printf("write: %016lx\n", rel_tbl[i].r_offset);
        }
        if (!strcmp((str_tbl + sym_tbl[ELF64_R_SYM(rel_tbl[i].r_info)].st_name), "connect")) {
            offsets[3] = rel_tbl[i].r_offset;
            // printf("connect: %016lx\n", rel_tbl[i].r_offset);
        }
        if (!strcmp((str_tbl + sym_tbl[ELF64_R_SYM(rel_tbl[i].r_info)].st_name), "getaddrinfo")) {
            offsets[4] = rel_tbl[i].r_offset;
            // printf("getaddrinfo: %016lx\n", rel_tbl[i].r_offset);
        }
        if (!strcmp((str_tbl + sym_tbl[ELF64_R_SYM(rel_tbl[i].r_info)].st_name), "system")) {
            offsets[5] = rel_tbl[i].r_offset;
            // printf("system: %016lx\n", rel_tbl[i].r_offset);
        }
    }
}

int __libc_start_main(int *(main) (int, char * *, char * *), 
    int argc, char * * ubp_av, void (*init) (void), void (*fini) (void),
    void (*rtld_fini) (void), void (* stack_end)) {
    /*************** hijack function ***************/

    int ret = -1, i = 0;
    sscanf(getenv("LOGGER_FD"), "%d", &log_fd);
    sscanf(getenv("SANDBOX_CONFIG"), "%s", cfg_path);
    cfg_fd = fopen(cfg_path, "r");
    if (cfg_fd == NULL) { perror("fopen(cfg)"); return -1; }
    // printf("%d %s\n", log_fd, cfg_path);

    FILE *fd = fopen("/proc/self/maps", "r");
    while ((c = fgetc(fd)) != '-') { str[i++] = c; }
    fclose(fd);
    str[i] = '\0';
    uint64_t proc_baseAddr;
    proc_baseAddr = strtoul(str, NULL, 16);
    // printf("@BASE: 0x%s = 0x%016lx\n", str, proc_baseAddr);

    int elf_fd = open("/proc/self/exe", O_RDONLY|O_SYNC);
    Elf64_Ehdr eh64;
    read_elf_header64(elf_fd, &eh64);
    // print_elf_header64(eh64);
    Elf64_Shdr* sh_tbl = malloc(eh64.e_shentsize * eh64.e_shnum);
    if (!sh_tbl) { perror("sh_tbl malloc:"); exit(-1); }
    read_section_header_table64(elf_fd, eh64, sh_tbl);
    // print_section_headers64(elf_fd, eh64, sh_tbl);

    uint64_t offsets[6] = {};
    collect_6_offset(elf_fd, eh64, sh_tbl, offsets); // print_symbols64(elf_fd, eh64, sh_tbl);
    // for (i = 0; i < 6; i++) { printf("%016lx ", offsets[i]); }
    // printf("\n\n");

    size_t page_sz = sysconf(_SC_PAGESIZE);
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if (handle != NULL) {
        __libc_start_main_OLD = dlsym(handle, "__libc_start_main");
        open_OLD = dlsym(handle, "open");
        read_OLD = dlsym(handle, "read");
        write_OLD = dlsym(handle, "write");
        connect_OLD = dlsym(handle, "connect");
        getaddrinfo_OLD = dlsym(handle, "getaddrinfo");
        system_OLD = dlsym(handle, "system");

        for (i = 0; i < 6; i++) {
            if (!offsets[i]) { continue; }

            uint64_t got_entry = proc_baseAddr + offsets[i];
            int ret = mprotect((int *)(got_entry & (~(page_sz - 1))), page_sz, PROT_WRITE | PROT_READ | PROT_EXEC);
            if (ret < 0) { perror("mprotect"); return -1; }
            int* addr = (int*)got_entry;

            if (i == 0) { *(size_t *)addr = (size_t)open_NEW; }
            else if (i == 1) { *(size_t *)addr = (size_t)read_NEW; }
            else if (i == 2) { *(size_t *)addr = (size_t)write_NEW; }
            else if (i == 3) { *(size_t *)addr = (size_t)connect_NEW; }
            else if (i == 4) { *(size_t *)addr = (size_t)getaddrinfo_NEW; }
            else if (i == 5) { *(size_t *)addr = (size_t)system_NEW; }
            // printf("src : %p/%p, dest=%p\n", open, open_OLD, open_NEW);
            // printf("got_entry = %p; *got_entry = 0x%llx\n", addr, *(uint64_t*)addr);
            // *(size_t *)addr = (size_t)open_NEW;
            // printf("got_entry = %p; *got_entry = 0x%llx\n", addr, *(uint64_t*)addr);
        }

        ret = __libc_start_main_OLD(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
    }
    else {
        fprintf(stderr, "%s\n", dlerror());
        exit(1);
    }

    fclose(cfg_fd);
    return ret;
}
