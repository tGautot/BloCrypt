#define BOOST_TEST_MODULE Simple TestMetaKeyIO
#include <boost/test/unit_test.hpp>
#include <MetaKey.hpp>

// TODO Write tests for edge cases (uint64t max val, name max length,...)
BOOST_AUTO_TEST_CASE(metakey_IO) {
    
    char samp_key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}; 
    MetaKey mk1(123LL, 456LL, "First Block for test hehehe", 16, samp_key);
    MetaKey mk2(789LL, 2023LL, "Second Block for test <|:)-/-<[:", 32, samp_key);
    MetaKey mk3(3333LL, 3337LL, "3", 8, samp_key);
    std::vector<MetaKey> mks{mk1, mk2, mk3};
    
    std::ofstream of("testfile_MetaKeyIO", std::ios::binary | std::ios::out);
    BOOST_CHECK_MESSAGE(of.is_open(), "Failed to open/create MetaKey IO testfile");
    MetaKey::MetaKeyVectorToFile(mks, of);
    of.close();

    std::ifstream inf("testfile_MetaKeyIO", std::ios::binary | std::ios::in);
    BOOST_CHECK_MESSAGE(inf.is_open(), "Failed to open MetaKey IO testfile");
    std::vector<MetaKey> decoded_mks = MetaKey::FileToMetaKeyVector(inf);
    inf.close();

    BOOST_TEST_INFO("Bad number of keys decoded, expected " << mks.size() << " but got " << decoded_mks.size());
    BOOST_CHECK_EQUAL(decoded_mks.size(), mks.size());

    int n = mks.size();
    for(int i = 0; i < n; i++){

        MetaKey mka = mks[i], mkb = decoded_mks[i];
        BOOST_TEST_INFO("Bad decoding of MetaKey, blockStt, expected " <<  mka.blockStt << " but got " << mkb.blockStt );
        BOOST_CHECK_EQUAL(mka.blockStt, mkb.blockStt);
        BOOST_TEST_INFO("Bad decoding of MetaKey, blockEnd, expected " <<  mka.blockEnd << " but got " << mkb.blockEnd );
        BOOST_CHECK_EQUAL(mka.blockEnd, mkb.blockEnd);
        BOOST_TEST_INFO("Bad decoding of MetaKey, blockName, expected " <<  mka.blockName << " but got " << mkb.blockName );
        BOOST_CHECK_EQUAL(mka.blockName.compare(mkb.blockName), 0);
        BOOST_TEST_INFO("Bad decoding of MetaKey, keySize, expected " <<  mka.keySize << " but got " << mkb.keySize );
        BOOST_CHECK_EQUAL(mka.keySize, mkb.keySize);
        if(mka.keySize != mkb.keySize) continue;
        for(int i = 0; i < mka.keySize; i++){
            BOOST_TEST_INFO("Bad decoding of MetaKey, key[" << i << "], expected " <<  mka.key[i] << " but got " << mkb.key[i] );
            BOOST_CHECK_EQUAL(mka.key[i], mkb.key[i]);
        
        }
    }
    BOOST_TEST_MESSAGE("metakey IO test succeeded");
}

