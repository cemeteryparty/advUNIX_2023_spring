#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <string>

#include <capstone/capstone.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <assert.h>
#include <unistd.h>
#include <elf.h>

#include <vector>
#include <map>

#include "elf_parser.h"
#include "ptools.h"

using namespace std;

void errquit(const char *msg) { perror(msg); exit(-1); }

cs_insn *insn;
static csh handle = 0;

int main(int argc, char *argv[]) {
    FILE * fp;
    fp = fopen("/tmp/debug.out", "w+");
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) { return -1; }
    map<range_t, map_entry_t> vmmap;
    map<range_t, map_entry_t>::iterator vi;

    pid_t child;
    if(argc < 2) {
        fprintf(stderr, "Usage: ./sdb ELF_FILE\n");
        return 0;
    }
    if((child = fork()) < 0) { errquit("fork"); }

    if (child == 0) { // child
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { errquit("TRACEME"); }
        if (execvp(argv[1], argv + 1) < 0) { errquit("execvp"); }
    }
    else {
        int wait_status;
        struct user_regs_struct regs; // saved_regs, 

        if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
        assert(WIFSTOPPED(wait_status));
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

        {
            if (load_maps(child, vmmap) > 0) {
                fprintf(fp, "## %zu map entries loaded.\n", vmmap.size());
                for (vi = vmmap.begin(); vi != vmmap.end(); vi++) {
                    fprintf(fp, "## %lx-%lx %04o %s %lx\n",
                        vi->second.range.begin, vi->second.range.end,
                        vi->second.perm, vi->second.name.c_str(), vi->second.offset
                    );
                }
            }
            else { errquit("## cannot load memory mappings.\n"); }
        } /* load_maps */

        range_t text_section;
        {
            char elf_filename[32];
            snprintf(elf_filename, 32, "/proc/%d/exe", child);
            elf_parser::Elf_parser ep_obj(elf_filename);
            vector<elf_parser::section_t> sections = ep_obj.get_sections();
            for (elf_parser::section_t &sec: sections) {
                if (sec.section_name == ".text") {
                    text_section.begin = text_section.end = sec.section_addr;
                    text_section.end += sec.section_size;
                }
            }
            fprintf(fp, ".text: 0x%lx~0x%lx\n", text_section.begin, text_section.end);
        } /* elf parse */

        if (WIFSTOPPED(wait_status)) {
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) { errquit("GETREGS"); }
            printf("** program '%s' loaded. entry point 0x%llx\n", argv[1], regs.rip);
        }

        string input, command;
        uint64_t address_arg;
        while (WIFSTOPPED(wait_status) && command != "quit") {

            /* default beh: print 5 instr */
            if (!ptrace(PTRACE_GETREGS, child, 0, &regs)) {
                size_t ci, count;
                unsigned char bytes40[40] = {0};
                for (ci = 0; ci < 5; ci++) {
                    uint64_t peek = ptrace(PTRACE_PEEKTEXT, child, regs.rip + 8 * ci, 0);
                    memcpy(bytes40 + 8 * ci, &peek, 8);
                    
                } /* load 40 bytes from rip, can be extend */

                ci = 0;
                count = cs_disasm(handle, bytes40, sizeof(bytes40), regs.rip, 0, &insn);
                if (count > 0) {
                    while (ci < 5) {
                        char bytes[64] = "";
                        if (insn[ci].address >= text_section.end) {
                            printf("** the address is out of the range of the text section.\n");
                            break;
                        }
                        printf("\t%lx: ", insn[ci].address);
                        for (ushort bi = 0; bi < insn[ci].size; bi++) {
                            snprintf(&bytes[bi * 3], 4, "%2.2x ", insn[ci].bytes[bi]);
                        }
                        printf("%-32s\t%-10s%s\n", bytes, insn[ci].mnemonic, insn[ci].op_str);
                        ci++;
                    }
                    cs_free(insn, count);
                }
                else { errquit("failed to run cs_disasm()"); }
            }
            else { errquit("GETREGS"); }
            
            bool looping;
            do {
                looping = false;
                printf("(sdb) "); getline(cin, input);
                size_t pos = input.find(' ');
                if (pos != string::npos) {
                    command = input.substr(0, pos);
                    input = input.substr(pos + 1);
                    if (input.find(' ') != string::npos) { command = "invalid"; }
                    else {
                        try { address_arg = stoul(input, nullptr, 16); }
                        catch (exception &e) { command = "invalid"; }
                    }
                }
                else if (input.length()) { command = input; input.clear(); }
                fprintf(fp, "<%s> <%ld>\n", command.c_str(), address_arg);


                if (command == "cont" && input.empty()) {
                    ptrace(PTRACE_CONT, child, 0, 0);
                    if (waitpid(child, &wait_status, 0) < 0) { errquit("waitpid"); }
                } 
                else if (command == "si" && input.empty()) {
                    if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) { errquit("PTRACE_SINGLESTEP"); }
                    if (waitpid(child, &wait_status, 0) < 0) { errquit("waitpid"); }
                }
                else if (command == "timetravel" && input.empty()) {
                    printf("timetravel\n");
                }
                else if (command == "anchor" && input.empty()) {
                    printf("anchor\n");
                }
                else if (command == "quit" && input.empty()) { exit(0); }
                else if (command == "break") {
                    printf("break @ 0x%lx\n", address_arg);
                }
                else { fprintf(stderr, "Q_Q: unknown command\n"); looping = true; }
            } while (looping);
        }
        printf("** the target program terminated.\n");
    }

    cs_close(&handle);
    fclose(fp);
    return 0;
}

