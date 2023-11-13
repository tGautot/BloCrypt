#define LOG(msg) \
    std::cout << __FILE__ << "(" << __LINE__ << "): " << msg << std::endl

#define ERR(msg) \
    std::cout << "\033[1;41;37mERROR!!!\033[0m " << msg << std::endl

#define FATAL(msg, code) \
    ERR(msg); exit(code)

