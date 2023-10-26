#include <iostream>
#include <getopt.h>
#include <fstream>
#include <sstream>

#include "AES.hpp"



typedef struct {int stt, end;} Interval;

unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };


void printArgHelp(){
    std::cout << "ArgHelp" << std::endl;
}

int main(int argc, char** argv){
    /**
     * Arguments that can be given:
     * 
     * --file -f PATH
     *      Path to file to encrypt
     * 
     * --key-size -k (128 | 192 | 256)
     *      Key size for AES
     * 
     *  TODO
     * --source-blocks -b expected format: [0-9]*-[0-9]*(:[0-9]*-[0-9])*
     *      Gives the offset in bytes from begining of inputfile for [start-end[ of data to encrypt
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
        {"key-file",      1, NULL, 'K'}, // TODO
        {"block-file",    1, NULL, 'B'}
    };
    const char *short_opt = "?df:k:b:";
    while ((c = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1){
        std::cout << c << " -> " << optarg << std::endl;
        switch (c)  {
        case 'f':
            filePath = optarg;
            break;
        case 'k':
            keySize = atoi(optarg);
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

    std::cout << "Got " << blockCnt << " blocks" << std::endl;
    for(int i = 0; i < blockCnt; i++){
        std::cout << blocks[i].stt << "-" << blocks[i].end << std::endl;
    }

    AES aes(keySize);

    // Check all blocks before encrypting
    for(int blk = 0; blk < blockCnt; blk++){
        int blkStt = blocks[blk].stt, blkEnd = blocks[blk].end;
        if(blkEnd < blkStt) printf("Invalid block (end<start): %d-%d", blkStt, blkEnd);
        if((blkEnd - blkStt)%16 != 0) printf("Invalid block, size must be multiple of 16 bytes: %d-%d", blkStt, blkEnd);
    }

    std::fstream file;
    file.open(filePath, std::ios::binary | std::ios::in | std::ios::out);
    for(int blk = 0; blk < blockCnt; blk++){
        int blkStt = blocks[blk].stt, blkEnd = blocks[blk].end;
        int blkSz = blkEnd - blkStt;
        unsigned char fData[blkSz];
        
        file.seekg(blkStt, std::ios::beg);
        file.read((char*)fData, blkSz*sizeof(char));
        
        unsigned char* encData;
        encData = (operation == 0) ? aes.EncryptECB(fData, blkSz, key) : aes.DecryptECB(fData, blkSz, key);

        file.seekp(blkStt, std::ios::beg);
        file.write((char*)encData, blkSz*sizeof(char));
    }




}

