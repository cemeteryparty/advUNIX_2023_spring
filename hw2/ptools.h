#ifndef __PTOOLS_H__
#define __PTOOLS_H__

#include <sys/types.h>
#include <map>
#include <string>
#include <capstone/capstone.h>

typedef struct range_s {
    uint64_t begin, end;
}   range_t;

typedef struct map_entry_s {
    range_t range;
    int perm;
    long offset;
    std::string name;
}   map_entry_t;

typedef struct instruction_s {
    std::string bytes;
    std::string opr;
    std::string opnd;
} instruction_t;

bool operator<(range_t r1, range_t r2);
int load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);

void dump_code(uint64_t addr, uint64_t code);

#endif /* __PTOOLS_H__ */
