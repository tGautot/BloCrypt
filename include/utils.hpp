#define LOG(msg) \
    std::cout << __FILE__ << "(" << __LINE__ << "): " << msg << std::endl

#define ERR(msg) \
    std::cout << "\033[1;41;37mERROR!!!\033[0m " << msg << std::endl

#ifdef __GLIBC__
#include <execinfo.h>
void printBacktrace() {
    void *array[10];
    size_t size;

    size = backtrace(array, 10);

    // Actual printing
    backtrace_symbols_fd(array, size, STDERR_FILENO);
}
#define PRT_BT() printBacktrace()

#else

#define PRT_BT() std::cout << "Compile program with gcc to get backtrace information" << std::endl;

#endif


#define FATAL(msg, code) \
    PRT_BT(); ERR(msg); exit(code)
