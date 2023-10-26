#include <iostream>
#include <getopt.h>
#include <fstream>
#include <sstream>

#include "AES.hpp"
#include "KeyGen.hpp"



typedef struct {int stt, end;} Interval;

void printArgHelp(){
    std::cout << "ArgHelp" << std::endl;
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
    int operation = 0; // 0: encrypt  1: decrypt

    std::ifstream blockFile;
    std::stringstream blockStrBuf;
    int c; opterr = 0;

    struct option long_opt[] = {
        {"file",          1, NULL, 'f'},
        {"decrypt",       0, NULL, 'd'},
        {"key-size",      1, NULL, 'k'},
        {"source-blocks", 1, NULL, 'b'},
        {"key-file",      1, NULL, 'K'},
        {"block-file",    1, NULL, 'B'}
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
            operation = 1;
            break;
        case 'B':
            blockFile.open(optarg);
            blockStrBuf << blockFile.rdbuf();
            optarg = (char*) blockStrBuf.str().c_str();
            // no break, Let it go through
        case 'b': {
            char *s = optarg; int clnCnt;
            printf("Parsing blocks in %s\n", s);
            for(clnCnt=0; s[clnCnt]; s[clnCnt]==':'?clnCnt++:*s++); // count occurences of ":" in the string
            blockCnt = clnCnt+1;
            blocks = (Interval*)malloc(blockCnt*sizeof(Interval));
            s = optarg;
            char* tok = strtok(s, "-:");
            int intrvl = 0;
            do {
                blocks[intrvl].stt = atoi(tok);
                tok = strtok(NULL, "-:");
                blocks[intrvl].end = atoi(tok);
                tok = strtok(NULL, "-:");
                intrvl++;
            } while(tok != NULL);
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
    for(int blk = 0; blk < blockCnt; blk++){
        int blkStt = blocks[blk].stt, blkEnd = blocks[blk].end;
        printf("Got block from %d to %d\n", blocks[blk].stt, blocks[blk].end);
        if(blkEnd < blkStt) {
            printf("Invalid block (end<start): %d-%d", blkStt, blkEnd);
            exit(1);
        }
        if((blkEnd - blkStt)%16 != 0) {
            printf("Invalid block, size must be multiple of 16 bytes: %d-%d", blkStt, blkEnd);
            exit(1);
        }
    }


    std::fstream file;
    file.open(filePath, std::ios::binary | std::ios::in | std::ios::out);
    
    KeyGen kgen(keySize, keySourceFile);
    unsigned char* key = (unsigned char*) malloc(sizeof(char) * keySize/8);
    bool saveKey = (operation == 0) && (keySourceFile == NULL || strcmp(keySourceFile, "") == 0);


    std::ofstream keyFile;

    if(saveKey){
        keyFile.open("keys.store", std::ios::binary | std::ios::out);
    }

    for(int blk = 0; blk < blockCnt; blk++){
        printf("Encrypting block %d of %d\n", blk+1, blockCnt); fflush(stdout);
        int blkStt = blocks[blk].stt, blkEnd = blocks[blk].end;
        int blkSz = blkEnd - blkStt;
        unsigned char fData[blkSz];
        
        file.seekg(blkStt, std::ios::beg);
        file.read((char*)fData, blkSz*sizeof(char));
        
        unsigned char* encData;
        kgen.genNextKey(key);
        encData = (operation == 0) ? aes.EncryptECB(fData, blkSz, key) : aes.DecryptECB(fData, blkSz, key);

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

