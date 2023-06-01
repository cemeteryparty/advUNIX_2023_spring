#include <fstream>
#include <string>
#include <iostream>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

bool fileExists(const fs::path &p) {
    std::error_code ec;
    return fs::is_regular_file(p, ec)? true: false;
}
int main(int argc, char const *argv[]) {
    string magic = string(argv[2]);

    // fs::current_path(argv[1]); // cd
    // cout << "now: " << fs::current_path() << '\n';

    for (const fs::directory_entry &dir_entry: fs::recursive_directory_iterator(argv[1])) {
        fs::path p = dir_entry;
        std::error_code ec;
        fs::path p_abs = fs::absolute(p);

        if (fs::is_regular_file(p, ec)) {
            // printf("File: %s\n", p_abs.string().c_str());

            string context;
            ifstream fd(p.string());
            while (getline(fd, context)) {
                // printf("%s\n", context.c_str());
                if (context == magic) {
                    // printf("[!] FOUND:\n");
                    // printf("\t\t%s\n", p_abs.string().c_str());

                    printf("%s\n", p_abs.string().c_str());
                }
            }
            fd.close();
        }
    }
    return 0;
}