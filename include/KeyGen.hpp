#include <fstream>



class KeyGen {
    private:
        int keySize;
        std::fstream src;

    public:
        KeyGen(int key_size);
        KeyGen(int key_size, char* srcPath);

        void setRandomGenSeed(std::string seed);

        void genNextKey(unsigned char* dest);

};