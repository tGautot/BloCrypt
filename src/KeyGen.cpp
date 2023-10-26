#include <random>
#include <string.h>
#include <functional>
#include <time.h>

#include "KeyGen.hpp"


using random_bytes_engine = std::independent_bits_engine<
    std::default_random_engine, 8, unsigned char>;

random_bytes_engine rbe;


KeyGen::KeyGen(int key_size) : keySize(key_size){
    rbe.seed(time(NULL));
}

KeyGen::KeyGen(int key_size, char* srcPath) : keySize(key_size){
    if(srcPath != NULL && strcmp(srcPath, "") !=0 ){
        printf("Keygen from file\n"); fflush(stdout);
        src.open(srcPath, std::ios::binary | std::ios::in);
    }
    rbe.seed(time(NULL));
}



void KeyGen::genNextKey(unsigned char* dest){
    if(src.is_open()){
        src.read((char*)dest, sizeof(char) * keySize/8);
        return;
    }
    
    std::generate(dest, dest + (sizeof(char) * keySize/8), std::ref(rbe));
}