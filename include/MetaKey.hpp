#ifndef _METAKEY_HPP_
#define _METAKEY_HPP_

#include <cstdint>
#include <fstream>
#include <string>
#include <iostream>
#include <vector>

/**
 * Class containing Key used for encryption of a block
 * As well as metadata about block
 */
class MetaKey {
    private:
    uint64_t blockStt, blockEnd;
    std::string blockName;
    uint8_t keySize; // in bytes
    char* key;

    public:
    MetaKey(){}
    MetaKey(uint64_t stt, uint64_t end, std::string name, uint8_t sz, char* k );


    bool toFile(std::ofstream& f);

    static MetaKey fromFile(std::ifstream& f);
    static void     MetaKeyVectorToFile(std::vector<MetaKey> keys, uint64_t n, std::ofstream& f);
    static std::vector<MetaKey> FileToMetaKeyVector(std::ifstream& f);

    // Mainly for tests
    friend bool operator==(const MetaKey& mk1, const MetaKey& mk2);
};

#endif