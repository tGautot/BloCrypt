#include <iostream>
#include <getopt.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif


#include "AES.hpp"
#include "KeyGen.hpp"
#include "MetaKey.hpp"
#include "utils.hpp"


#define OP_ENCR 0
#define OP_DECR 1

typedef struct {int stt, end; std::string name;} Interval;

void printArgHelp(){
    std::cout << "ArgHelp" << std::endl;
    // TODO
}


// From
// https://stackoverflow.com/questions/1413445/reading-a-password-from-stdcin
void setStdinEcho(bool enable = true)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

Interval* parseBlockString(char* s, int* n){
    int clnCnt;
    printf("Parsing blocks in %s\n", s);
    for(clnCnt=0; s[clnCnt]; s[clnCnt]==':'?clnCnt++:*s++); // count occurences of ":" in the string
    *n = clnCnt+1;
    printf("Found %d blocks\n", *n);
    Interval* blocks = (Interval*)malloc((*n)*sizeof(Interval));
    s = optarg;
    char* tok = s;
    
    for(int intrvl = 0;; intrvl++) {
        //printf("AAA, %s\n", tok);
        int ofst = 0;
        while(tok[ofst] != '-' && tok[ofst] != 0){ofst++;} // Go to next '-'
        if(tok[ofst] == 0) {
            //printf("Big oopsie\n");
            FATAL("Error while parsing blocks, missing block's end", 1);
        }
        tok[ofst] = 0;
        blocks[intrvl].stt = atoi(tok);

        tok = tok + ofst + 1; ofst = 0;
        //printf("BBB, %s\n", tok);
        while(tok[ofst] != '-' && tok[ofst] != ':' && tok[ofst] != 0){ofst++;} // Go to next '-' or ':'
        char nxtDelim = tok[ofst];
        tok[ofst] = 0;
        blocks[intrvl].end = atoi(tok);
        tok = tok + ofst + 1; ofst = 0;
        
        //printf("CCC, %s\n", tok);
        if(nxtDelim == 0){
            // Cant do assignment instantly, causes sigsev
            std::string intrvlStr = std::to_string(intrvl);
            blocks[intrvl].name = intrvlStr;
            return blocks; }
    
        
        if(nxtDelim == ':'){ 
            // Cant do assignment instantly, causes sigsev
            std::string intrvlStr = std::to_string(intrvl);
            blocks[intrvl].name = intrvlStr;
            
            continue; }
        

        //printf("DDD, %s\n", tok);
        while(tok[ofst] != ':' && tok[ofst] != 0){ofst++;} // Go to next  ':'        
        tok[ofst] = 0;
        blocks[intrvl].name.assign(tok);
        tok = tok + ofst + 1;

    }
    return blocks;
}

int main(int argc, char** argv){
    /**
     * Arguments that can be given:
     * 
     * --decrypt -d do decryption instead of encryption
     * 
     * --file -f PATH
     *      Path to file to encrypt
     * 
     * --key-size -k (128 | 192 | 256)
     *      Key size for AES
     * 
     * --source-blocks -b expected format: [0-9]+-[0-9]+(:[0-9]+-[0-9]+)*
     *      Gives the offset in bytes from begining of inputfile for [start-end[ of data to encrypt
     * 
     * --key-file -K path_to_file 
     *      Gives path to file containing keys needed for decryption
     * 
     * --block-file -B path_to_file
     *      Give path to file containing description of blocks (same regex as -b)
    */

    char* filePath;
    int keySize;
    Interval* blocks;
    int blockCnt;
    int operation = OP_ENCR; 

    std::ifstream blockFile;
    std::stringstream blockStrBuf;
    int c; opterr = 0;

    struct option long_opt[] = {
        {"file",             1, NULL, 'f'},
        {"decrypt",          0, NULL, 'd'},
        {"key-size",         1, NULL, 'k'},
        {"source-blocks",    1, NULL, 'b'},
        {"key-file",         1, NULL, 'K'},
        {"block-file",       1, NULL, 'B'},
        {"decrypt-block-id", 1, NULL, 'i'},
        {"print-metadata",   0, NULL, 'p'}
    };
    const char *short_opt = "df:k:b:B:K:?";
    char *keySourceFile = NULL;
    while ((c = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1){
        switch (c)  {
        case 'f':
            filePath = optarg;
            break;
        case 'k':
            keySize = atoi(optarg);
            break;
        case 'K':
            keySourceFile = optarg;
            break;
        case 'd':
            operation = OP_DECR;
            break;
        case 'B':
            blockFile.open(optarg);
            blockStrBuf << blockFile.rdbuf();
            optarg = (char*) blockStrBuf.str().c_str();
            // no break, Let it go through
        case 'b': {
            char *s = optarg; int clnCnt;
            blocks = parseBlockString(s, &blockCnt);
            printf("Parsing finished, found %d blocks\n", blockCnt);
            break; }
        case '?':
            printArgHelp();
            return 1;
        default:
            abort ();
        }
    }

    if(blockFile.is_open()) blockFile.close();

    AES aes(keySize);

    // Check all blocks before encrypting
    printf("Pre-checking all %d blocks\n", blockCnt);
    for(int blk = 0; blk < blockCnt; blk++){
        int blkStt = blocks[blk].stt, blkEnd = blocks[blk].end;
        printf("Got block from %d to %d (%s)\n", blocks[blk].stt, blocks[blk].end, blocks[blk].name.c_str());
        if(blkEnd < blkStt) {
            printf("Invalid block (end<start): %d-%d", blkStt, blkEnd);
            exit(1);
        }
        if((blkEnd - blkStt)%16 != 0) {
            printf("Invalid block, size must be multiple of 16 bytes: %d-%d", blkStt, blkEnd);
            exit(1);
        }
    }
    return 0;


    std::fstream file;
    file.open(filePath, std::ios::binary | std::ios::in | std::ios::out);

    KeyGen kgen(keySize, keySourceFile);
    unsigned char* key = (unsigned char*) malloc(sizeof(char) * keySize/8);
    bool saveKey = (operation == OP_ENCR) && (keySourceFile == NULL || strcmp(keySourceFile, "") == 0);

    std::string password = "";
    if(keySourceFile == NULL){
        //setStdinEcho(false);
        std::cout << "No key source file was specified, please enter your password: ";
        getline(std::cin, password);
        if(password != ""){
            kgen.setRandomGenSeed(password);
        } else {
            printf("Empty password, using default key generation\n");
        }
        setStdinEcho(true);
    }

    std::ofstream keyFile;

    if(saveKey){
        keyFile.open("keys.store", std::ios::binary | std::ios::out);
    }

    // Could be very good, need to study openmp a bit
    // #pragma omp parallel for
    for(int blk = 0; blk < blockCnt; blk++){
        printf("Encrypting block %d of %d\n", blk+1, blockCnt); fflush(stdout);
        int blkStt = blocks[blk].stt, blkEnd = blocks[blk].end;
        int blkSz = blkEnd - blkStt;
        unsigned char fData[blkSz];
        
        file.seekg(blkStt, std::ios::beg);
        file.read((char*)fData, blkSz*sizeof(char));
        
        unsigned char* encData;
        kgen.genNextKey(key);
        encData = (operation == OP_ENCR) ? aes.EncryptECB(fData, blkSz, key) : aes.DecryptECB(fData, blkSz, key);

        if(saveKey) {
            keyFile.write((const char*)key, sizeof(char) * keySize/8);
        }

        file.seekp(blkStt, std::ios::beg);
        file.write((char*)encData, blkSz*sizeof(char));
    }

    file.close();
    if(saveKey) {
        keyFile.close();
        printf("============================================\n");
        printf("THE KEYS USED TO ENCRYPT YOUR DATA HAVE BEEN\n");
        printf("SAVED TO THE FILE \"keys.store\" DON'T LOSE IT\n");
        printf("============================================\n");
        fflush(stdout);
    }
    free(key);
    free(blocks);


}

