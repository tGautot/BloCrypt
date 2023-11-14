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
#define OP_PRT_MD 2

typedef struct {int stt, end; std::string name;} Interval;

void printArgHelp(){
    std::cout << "ArgHelp" << std::endl;
    // TODO
}


// From
// https://stackoverflow.com/questions/1413445/reading-a-password-from-stdcin
void setStdinEcho(bool enable = true){
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
        int ofst = 0;
        while(tok[ofst] != '-' && tok[ofst] != 0){ofst++;} // Go to next '-'
        if(tok[ofst] == 0) {
            FATAL("Error while parsing blocks, missing block's end", 1);
        }
        tok[ofst] = 0;
        blocks[intrvl].stt = atoi(tok);

        tok = tok + ofst + 1; ofst = 0;
        while(tok[ofst] != '-' && tok[ofst] != ':' && tok[ofst] != 0){ofst++;} // Go to next '-' or ':'
        char nxtDelim = tok[ofst];
        tok[ofst] = 0;
        blocks[intrvl].end = atoi(tok);
        tok = tok + ofst + 1; ofst = 0;
        
        if(nxtDelim == 0){
            // Cant do assignment instantly, causes sigsev, dunno why
            std::string intrvlStr = std::to_string(intrvl);
            blocks[intrvl].name = intrvlStr;
            return blocks; }
    
        
        if(nxtDelim == ':'){ 
            // Cant do assignment instantly, causes sigsev, dunno why
            std::string intrvlStr = std::to_string(intrvl);
            blocks[intrvl].name = intrvlStr;
            continue; }
        

        while(tok[ofst] != ':' && tok[ofst] != 0){ofst++;} // Go to next  ':'        
        nxtDelim = tok[ofst];
        tok[ofst] = 0;
        blocks[intrvl].name.assign(tok);

        if(nxtDelim == 0) return blocks;
        
        tok = tok + ofst + 1;

    }
    return blocks;
}

unsigned char aes_iv[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

void encrypt(char* filePath, char* keySourceFile, int keySize, Interval* blocks, uint64_t blockCnt){
    std::cout << "Started encryption" << std::endl;
    // If no key source file was given, will generate keys randomly,
    // and save them as MetaKey to file for later decryption 
    bool saveKey = (keySourceFile == NULL || strcmp(keySourceFile, "") == 0);

    if( !((!saveKey) ^ (blocks!=NULL)) ){ // Block info can only come from blocks var (x)or MetaKey file, not both
        FATAL("Calling encrypt method with both key sourcefile and blocks data (or none)", 1);
    }
    
    KeyGen kgen(keySize);

    std::string password = "";
    if(saveKey){ // KeyGen will only be used if savekey is true
        setStdinEcho(false);
        std::cout << "No key source file was specified, please enter your password: ";
        getline(std::cin, password);
        if(password != ""){
            kgen.setRandomGenSeed(password);
        } else {
            printf("Empty password, using default key generation\n");
        }
        setStdinEcho(true);
    }


    std::fstream file;
    file.open(filePath, std::ios::binary | std::ios::in | std::ios::out);
    
    std::fstream keyFile;
    if(saveKey){
        keyFile.open("keys.store", std::ios::binary | std::ios::out);
        if(!keyFile.is_open()) {FATAL("Failed to create file to store encryption keys", 1);}
        keyFile.write((const char*)&blockCnt, sizeof(uint64_t));
    } else {
        keyFile.open(keySourceFile, std::ios::binary | std::ios::in);
        if(!keyFile.is_open()) {FATAL("Failed to open key sourcefile", 1);}
    }

    MetaKey mk;

    unsigned char* key = (unsigned char*) malloc(sizeof(char) * keySize/8);

    // Could be very good, need to study openmp a bit
    // #pragma omp parallel for
    int blockKeySize;
    for(uint64_t blk = 0; blk < blockCnt; blk++){
        printf("Encrypting block %ld / %ld\n", blk+1, blockCnt); fflush(stdout);

        if(saveKey){
            kgen.genNextKey(key);
    
            mk.blockStt = blocks[blk].stt;
            mk.blockEnd = blocks[blk].end;
            mk.blockName.assign(blocks[blk].name);
            mk.setKey(keySize/8, (char*) key);
        } else {
            MetaKey::fromFile(keyFile, &mk);
        }

        blockKeySize = mk.keySize*8;
        int blkSz = mk.blockEnd - mk.blockStt;
        unsigned char fData[blkSz];
        
        file.seekg(mk.blockStt, std::ios::beg);
        file.read((char*)fData, blkSz*sizeof(char));
        
        unsigned char* encData;

        AES aes(blockKeySize);
        encData = aes.EncryptCBC(fData, blkSz, key, aes_iv);

        if(saveKey) {
            mk.toFile(keyFile);
        }

        file.seekp(blocks[blk].stt, std::ios::beg);
        file.write((char*)encData, blkSz*sizeof(char));
    }

    file.close();
    keyFile.close();
    free(key);
    if(saveKey) {
        printf("============================================\n");
        printf("THE KEYS USED TO ENCRYPT YOUR DATA HAVE BEEN\n");
        printf("SAVED TO THE FILE \"keys.store\" DON'T LOSE IT\n");
        printf("============================================\n");
        fflush(stdout);
    }
}

void decrypt(char* filePath, char* keySourceFile){
    std::cout << "Starting decryption" << std::endl;

    std::fstream keyFile(keySourceFile, std::ios::binary | std::ios::in), file(filePath, std::ios::binary | std::ios::in | std::ios::out);
    MetaKey mk;
    int blockKeySize;
    uint64_t blockCnt;
    keyFile.read((char*)&blockCnt, sizeof(uint64_t)); 
    for(uint64_t blk = 0; blk < blockCnt; blk++){
        bool res = MetaKey::fromFile(keyFile, &mk);
        if(!res) break;
        printf("Decrypting block %s (%ld / %ld)\n", mk.blockName.c_str(), blk, blockCnt); fflush(stdout);


        blockKeySize = mk.keySize*8;
        int blkSz = mk.blockEnd - mk.blockStt;
        unsigned char fData[blkSz];
        
        file.seekg(mk.blockStt, std::ios::beg);
        file.read((char*)fData, blkSz*sizeof(char));
        
        unsigned char* encData;

        AES aes(blockKeySize);
        encData = aes.DecryptCBC(fData, blkSz, (unsigned char*) mk.key, aes_iv);


        file.seekp(mk.blockStt, std::ios::beg);
        file.write((char*)encData, blkSz*sizeof(char));
    }
}

void printMetaData(char* keySourceFile){
    bool nothing = (keySourceFile == NULL || strcmp(keySourceFile, "") == 0);
    if(nothing){
        printf("Please provide a KeyStore file\n");
        return;
    }
    std::fstream keyFile(keySourceFile, std::ios::binary | std::ios::in);
    uint64_t blockCnt;
    keyFile.read((char*)&blockCnt, sizeof(uint64_t)); 
    printf("KeyStore file contains keys for %ld blocks\n", blockCnt);
    MetaKey mk;
    for(int i = 0; i < blockCnt; i++){
        bool res = MetaKey::fromFile(keyFile, &mk);
        if(!res) {FATAL("Reached end of key file before advertised",1);}
        printf("==========================================================\n");
        printf("\tBlock name          : %s\n", mk.blockName.c_str());
        printf("\tBlock starts at byte: %ld\n", mk.blockStt);
        printf("\tBlock ends   at byte: %ld\n", mk.blockEnd);
        printf("\tBlock's key size    : %d (bytes)\n" , mk.keySize); 
    }
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
     * --source-blocks -b expected format: [0-9]+-[0-9]+(-[A-Z]*)?(:[0-9]+-[0-9]+(-[A-Z]*)?)*
     *      Gives the offset in bytes from begining of inputfile for [start-end[ of data to encrypt
     * 
     * --key-file -K path_to_file 
     *      Gives path to file containing keys needed for decryption
     * 
     * --block-file -B path_to_file
     *      Give path to file containing description of blocks (same regex as -b)
    */

    char* filePath;
    int keySize = 256;
    Interval* blocks = NULL;
    int blockCnt = 0;
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
    const char *short_opt = "pdf:k:b:B:K:?";
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
        case 'p':
            operation = OP_PRT_MD;
            break;
        case '?':
            printArgHelp();
            return 0;
        default:
            abort ();
        }
    }
    if(operation == OP_PRT_MD) {
        printMetaData(keySourceFile);
        return 0;
    }

    if(blockFile.is_open()) blockFile.close();

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

    if(operation == OP_ENCR) encrypt(filePath, keySourceFile, keySize, blocks, blockCnt);
    else                     decrypt(filePath, keySourceFile);

    free(blocks);


}

