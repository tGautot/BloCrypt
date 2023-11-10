#include <MetaKey.hpp>


MetaKey::MetaKey(uint64_t stt, uint64_t end, std::string name, uint8_t sz, char* k )
    :blockStt(stt), blockEnd(end), blockName(name), keySize(sz){
    if(name.size() >= 256){
        std::cout << "ERROR::MetaKey::MetaKey() Cannot have name longer than 256 bytes" << std::endl;
        throw (name.size());
    }
    for(int i = 0; i < sz; i++) key[i] = k[i];
}

bool MetaKey::toFile(std::ofstream& f){
    f.write((char*)&blockStt, sizeof(uint64_t));
    f.write((char*)&blockEnd, sizeof(uint64_t));
    uint8_t sz = blockName.size();
    f.write((char*)&sz, sizeof(uint8_t));
    f << blockName;
    f.write((char*)&keySize, sizeof(uint8_t));
    f.write(        key, keySize);
    
    return true;
}

MetaKey MetaKey::fromFile(std::ifstream& f){
    uint64_t bs, be;
    f.read((char*)&bs, sizeof(uint64_t));
    f.read((char*)&be, sizeof(uint64_t));
    
    uint8_t sz;
    f.read((char*)&sz, sizeof(uint8_t));
    char* name = (char*)malloc((sz+1) * sizeof(char));
    name[sz] = 0; // Make sure it is 0 terminated
    f.read(name, sz*sizeof(char));
    std::string strName(name);

    uint8_t ks;
    f.read((char*)&ks, sizeof(uint8_t));
    char* key = (char*) malloc(ks*sizeof(char));
    f.read(key, ks*sizeof(char));
    return MetaKey(bs,be,strName,ks,key);
}

void MetaKey::MetaKeyVectorToFile(std::vector<MetaKey> keys, uint64_t n, std::ofstream& f){
    //f.seekp(0, std::ios::beg);
    f.write((char*)&n, sizeof(uint64_t));
    for(int i = 0; i < n; i++){
        keys[i].toFile(f);
    }
}

std::vector<MetaKey> MetaKey::FileToMetaKeyVector(std::ifstream& f){
    uint64_t n;
    f.read((char*)&n, sizeof(uint64_t));
    std::vector<MetaKey> vec(n);
    for(int i = 0; i < n; i++){
        vec[i] = MetaKey::fromFile(f);
    }
    return vec;
}

bool operator==(const MetaKey& mk1, const MetaKey& mk2){
    bool ans = true;
    ans = ans && (mk1.blockStt == mk2.blockStt && mk1.blockEnd == mk2.blockEnd)
              && (mk1.blockName.compare(mk2.blockName) == 0)
              && (mk1.keySize == mk2.keySize);
    if(!ans) return false;
    for(int i = 0; i < mk1.keySize; i++){
        ans = ans && (mk1.key[i] == mk2.key[i]);
    }
    return ans;
}