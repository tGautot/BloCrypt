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
    public:
    uint64_t blockStt, blockEnd;
    std::string blockName;
    uint8_t keySize; // in bytes
    char* key;

    public:
    MetaKey(){key = NULL;}
    MetaKey(uint64_t stt, uint64_t end, std::string name, uint8_t sz, char* k );

    void setKey(uint8_t keySz, char* newKey);

    bool toFile(std::ostream& f);
    static bool fromFile(std::istream& f, MetaKey* mk);

    static void     MetaKeyVectorToFile(std::vector<MetaKey> keys, std::ofstream& f);
    static std::vector<MetaKey> FileToMetaKeyVector(std::ifstream& f);

    // Mainly for tests
    friend bool operator==(const MetaKey& mk1, const MetaKey& mk2);
};

#endif