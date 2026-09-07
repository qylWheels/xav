// Trigger program for the dynamic_code_loading_rule:
// mprotect()s a region with PROT_WRITE | PROT_EXEC.
#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <iostream>

int main() {
    std::size_t page = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
    void* p = ::mmap(nullptr, page, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        std::cerr << "mmap failed" << std::endl;
        return 1;
    }
    if (::mprotect(p, page, PROT_WRITE | PROT_EXEC) < 0) {
        std::cerr << "mprotect(W|X) failed" << std::endl;
    }
    ::munmap(p, page);
    return 0;
}
