#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

void errquit(const char *msg) {
    perror(msg);
    exit(-1);
}

int main(int argc, char *argv[]) {
    pid_t child;
    if(argc < 2) {
        fprintf(stderr, "Usage: ./solver ELF_FILE\n");
        return 0;
    }
    if((child = fork()) < 0) { errquit("fork"); }

    if (child == 0) { // child
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) { errquit("TRACEME"); }
        if (execvp(argv[1], argv + 1) < 0) { errquit("execvp"); }
    }
    else { // parent
        int magic = 0, N_timeline = 512;
        size_t magic_ptr;
        int wait_status, count_INT3 = 0, i;
        struct user_regs_struct tleap_regs, regs;
        if (waitpid(child, &wait_status, 0) < 0) { errquit("waitpid"); }
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

        while (WIFSTOPPED(wait_status)) {
            if (count_INT3 == 1) {
                /*
                896d:   cc                      int3 (1st) 
                896e:   ba 0a 00 00 00          mov    edx,0xa <- rip after 1st INT_3
                8973:   be 30 00 00 00          mov    esi,0x30
                8978:   48 8d 05 49 f8 0c 00    lea    rax,[rip+0xcf849]  # d81c8 <magic>
                897f:   48 89 c7                mov    rdi,rax
                8982:   e8 29 f9 ff ff          call   82b0 <_init+0x2b0>
                8987:   cc                      int3 (2nd)
                */
                if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) { errquit("GETREGS"); }
                magic_ptr = ptrace(PTRACE_PEEKTEXT, child, regs.rip + 13, 0) & 0xffffffff;
                magic_ptr += regs.rip + (0x897f - 0x896e);

                // magic_ptr = regs.rip + 0xcf849 + (0x897f - 0x896e); // only for sample...
            }

            else if (count_INT3 == 3) { // finish oracle_connect()
                if (ptrace(PTRACE_GETREGS, child, 0, &tleap_regs) != 0) { errquit("GETREGS"); }
            }
            else if (count_INT3 == 5) {
                if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) { errquit("GETREGS"); }
                // printf("%llu %d %d\n", regs.rax, sizeof(long long), sizeof(long));
                if ((int)regs.rax < 0  && (++magic) < N_timeline) { // 4294967295L
                    int M = magic;
                    unsigned char code[9];
                    unsigned long *lcode = (unsigned long *)code;
                    for (i = 0; i < 9; i++) {
                        code[i] = M & 1? '1': '0';
                        M >>= 1;
                    }

                    /* insert new magic */
                    if (ptrace(PTRACE_POKETEXT, child, magic_ptr, *lcode) != 0) { errquit("ptrace(PTRACE_POKETEXT)"); }
                    lcode = (unsigned long *)(code + 1);
                    if (ptrace(PTRACE_POKETEXT, child, magic_ptr + 1, *lcode) != 0) { errquit("ptrace(PTRACE_POKETEXT)"); }
                    
                    /* restore to oracle_connect */
                    if (ptrace(PTRACE_SETREGS, child, 0, &tleap_regs) != 0) { errquit("PTRACE_SETREGS"); }
                    count_INT3 = 3;
                }
            }

            ptrace(PTRACE_CONT, child, 0, 0);
            if (waitpid(child, &wait_status, 0) < 0) { errquit("waitpid"); }
            count_INT3++;
        }
    }

    return 0;
}

