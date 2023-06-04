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

#include <unordered_map>
#include <vector>
#include <map>

#include "elf_parser.h"
#include "ptools.h"

using namespace std;

void errquit(const char *msg) { perror(msg); exit(-1); }

cs_insn *insn;
static csh handle = 0;
static uint64_t const QWORD_1 = 0xffffffffffffffff;
static uint64_t const CC_MASK = 0xffffffffffffff00;

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
    if (child == 0) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { errquit("TRACEME"); }
        if (execvp(argv[1], argv + 1) < 0) { errquit("execvp"); }
    } /* child: TRACEME */
    else {
        int wait_status;
        struct user_regs_struct regs;

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
                    // if ((vi->second.perm & 0x01) == 0x01 && baseaddr == 0) { baseaddr = vi->second.range.begin; }
                }
            }
            else { errquit("## cannot load memory mappings.\n"); }
        } /* load_maps */

        size_t text_sz = 0;
        range_t text_section, r;
        {
            char elf_filename[32];
            snprintf(elf_filename, 32, "/proc/%d/exe", child);
            elf_parser::Elf_parser ep_obj(elf_filename);
            vector<elf_parser::section_t> sections = ep_obj.get_sections();
            for (elf_parser::section_t &sec: sections) {
                if (sec.section_name == ".text") {
                    text_sz = sec.section_size;
                    text_section.begin = text_section.end = sec.section_addr;
                    text_section.end += sec.section_size;
                }
            }
            fprintf(fp, ".text: 0x%lx~0x%lx\n", text_section.begin, text_section.end);
        } /* elf parse */

        uint64_t peek;
        size_t ci = 0, count;
        map<uint64_t, instruction_t> ins_mapping;
        map<uint64_t, instruction_t>::iterator mi;
        if (WIFSTOPPED(wait_status)) {
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) { errquit("GETREGS"); }
            printf("** program '%s' loaded. entry point 0x%llx\n", argv[1], regs.rip);

            /* use map<address, instruction> to mem text section */
            uint64_t entry_ptr = text_section.begin;
            unsigned char *text_dat = (unsigned char *)malloc((text_sz + 8) * sizeof(unsigned char));
            while (entry_ptr < text_section.end) {
                peek = ptrace(PTRACE_PEEKTEXT, child, entry_ptr, 0); // int64_t
                memcpy(text_dat + ci, &peek, 8);
                entry_ptr += 8; ci += 8;
            }
            count = cs_disasm(handle, text_dat, text_sz + 8, text_section.begin, 0, &insn);
            if (count <= 0) { errquit("failed to run cs_disasm()"); }
            for (ci = 0; ci < count; ci++) {
                if (insn[ci].address >= text_section.end) { break; }
                char bytes[64] = "";
                for (ushort bi = 0; bi < insn[ci].size; bi++) {
                    snprintf(&bytes[bi * 3], 4, "%2.2x ", insn[ci].bytes[bi]);
                }
                instruction_t ins_;
                ins_.bytes = string(bytes);
                ins_.opr = string(insn[ci].mnemonic);
                ins_.opnd = string(insn[ci].op_str);
                ins_mapping[insn[ci].address] = ins_;
            }
            cs_free(insn, count);
            free(text_dat);
            for (mi = ins_mapping.begin(); mi != ins_mapping.end(); mi++) {
                fprintf(fp, "\t%lx: ", mi->first);
                fprintf(fp, "%-32s\t%-10s%s\n",
                    mi->second.bytes.c_str(),
                    mi->second.opr.c_str(),
                    mi->second.opnd.c_str()
                );
            }
        } /* initialize debugger */

        string input, command = "init";
        uint64_t address_arg;
        unordered_map<uint64_t, uint64_t> bk_map; // addr: 8bytes code
        unordered_map<uint64_t, uint64_t>::iterator bit;

        char mem_fname[32];
        snprintf(mem_fname, 32, "/proc/%d/mem", child);
        map<range_t, void*> anchor_snap;
        map<range_t, void*>::iterator ait;
        struct user_regs_struct anchor_regs;
        while (WIFSTOPPED(wait_status) && command != "quit") {
            for (bit = bk_map.begin(); bit != bk_map.end(); bit++) {
                peek = bit->second;
                if (ptrace(PTRACE_POKETEXT, child, bit->first, (peek & CC_MASK) | 0xcc) != 0) { errquit("ptrace(POKETEXT)"); }
            } /* insert the used breakpoint */
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) { errquit("GETREGS"); }

            // printf("rip: 0x%llx\n", regs.rip);

            uint64_t off = command == "cont"? 1: 0;
            if (bk_map.find(regs.rip - off) != bk_map.end()) {
                regs.rip = regs.rip - off;
                printf("** hit a breakpoint at 0x%llx\n", regs.rip);
                if (ptrace(PTRACE_POKETEXT, child, regs.rip, bk_map[regs.rip]) != 0) { errquit("ptrace(POKETEXT)"); }
                if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) { errquit("ptrace(SETREGS)"); }
            } /* restore breakpoint */

            if (command != "anchor" && command != "break"){
                ci = 0; mi = ins_mapping.find(regs.rip);
                while (mi != ins_mapping.end() && ci < 5) {
                    printf("\t%lx: ", mi->first);
                    printf("%-32s\t%-10s%s\n",
                        mi->second.bytes.c_str(),
                        mi->second.opr.c_str(),
                        mi->second.opnd.c_str()
                    );
                    ci++; mi++;
                }
                if (ci < 5) { printf("** the address is out of the range of the text section.\n"); }
            } /* write 5 instr to stdout */

            bool looping; do {
                looping = false;
                printf("(sdb) "); getline(cin, input);
                {
                    size_t pos = input.find(' ');
                    address_arg |= QWORD_1;
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
                } /* parse user input */

                if (command == "cont" && input.empty()) {
                    ptrace(PTRACE_CONT, child, 0, 0);
                    if (waitpid(child, &wait_status, 0) < 0) { errquit("waitpid"); }
                } /* continue */
                else if (command == "si" && input.empty()) {
                    if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) { errquit("PTRACE_SINGLESTEP"); }
                    if (waitpid(child, &wait_status, 0) < 0) { errquit("waitpid"); }
                } /* step */
                else if (command == "timetravel" && input.empty()) {
                    if (anchor_snap.empty()) {
                        fprintf(stderr, "X_X: invalid to do timetravel before `anchor`\n");
                        looping = true; continue;
                    }
                    int mem_fd;
                    if ((mem_fd = open(mem_fname, O_RDWR)) < 0) { errquit("timetravel: open mem file"); }
                    for (ait = anchor_snap.begin(); ait != anchor_snap.end(); ait++) {
                        r = ait->first;
                        if (pwrite(mem_fd, ait->second, r.end - r.begin, r.begin) < 0) { errquit("timetravel: pwrite"); }
                    }
                    if (ptrace(PTRACE_SETREGS, child, 0, &anchor_regs) != 0) { errquit("timetravel: SETREGS"); }
                }
                else if (command == "anchor" && input.empty()) {
                    if (ptrace(PTRACE_GETREGS, child, 0, &anchor_regs) != 0) { errquit("GETREGS"); }
                    int mem_fd;
                    if ((mem_fd = open(mem_fname, O_RDONLY)) < 0) { errquit("anchor: open mem file"); }
                    for (vi = vmmap.begin(); vi != vmmap.end(); vi++) {
                        r = vi->first;
                        if ((vi->second.perm & 0x02) == 0x02) {
                            anchor_snap[r] = NULL;
                            if ((anchor_snap[r] = mmap(NULL, r.end - r.begin, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) { errquit("anchor: mmap"); }
                            if (pread(mem_fd, anchor_snap[r], r.end - r.begin, r.begin) < 0) { errquit("anchor: pread"); }
                        }
                    }
                    close(mem_fd);
                    printf("** dropped an anchor\n");
                    looping = true;
                }
                else if (command == "quit" && input.empty()) { exit(0); }
                else if (command == "break" && (address_arg & QWORD_1) != QWORD_1) {
                    if (ins_mapping.find(address_arg) == ins_mapping.end()) {
                        fprintf(stderr, "X_X: invalid to break at %lx\n", address_arg);
                        continue;
                    }
                    peek = ptrace(PTRACE_PEEKTEXT, child, address_arg, 0);
                    bk_map[address_arg] = peek;
                    if (ptrace(PTRACE_POKETEXT, child, address_arg, (peek & CC_MASK) | 0xcc) != 0) { errquit("ptrace(POKETEXT)"); }
                    

                    // uint64_t entry_ptr = text_section.begin;
                    // while (entry_ptr < text_section.end) {
                    //     peek = ptrace(PTRACE_PEEKTEXT, child, entry_ptr, 0); // int64_t
                    //     dump_code(entry_ptr, peek);
                    //     entry_ptr += 8;
                    // }
                    printf("** set a breakpoint at 0x%lx\n", address_arg);
                } /* break */
                else { fprintf(stderr, "Q_Q: unknown command\n"); looping = true; }
            } while (looping);
        }
        printf("** the target program terminated.\n");
    }

    cs_close(&handle);
    fclose(fp);
    return 0;
}

