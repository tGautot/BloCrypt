#include <random>

#include <functional>

#include "KeyGen.hpp"


using random_bytes_engine = std::independent_bits_engine<
    std::default_random_engine, 8, unsigned char>;


KeyGen::KeyGen(int key_size) : keySize(key_size){}

KeyGen::KeyGen(int key_size, char* srcPath) : keySize(key_size){
    src.open(srcPath, std::ios::binary | std::ios::in);
}

void KeyGen::getKey(unsigned char* dest){
    if(src.is_open()){
        src.read((char*)dest, sizeof(char) * keySize/8);
        return;
    }
    random_bytes_engine rbe;
    std::generate(dest, dest + (sizeof(char) * keySize/8), std::ref(rbe));
}