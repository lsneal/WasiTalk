#include "client.hpp"

void    Client::EncryptAndSendAES(std::string public_key)
{
    std::vector<unsigned char> key(64);
    std::vector<unsigned char> keyHex(64);
    std::vector<unsigned char> iv(32);
    std::vector<unsigned char> ivHex(32);
    //std::string aesEncryptB64;

    generateAESKeyAndIV(key, iv);
    convertToHex(key, keyHex); // KEY
    convertToHex(iv, ivHex); // IV 
    std::cout << "Key:" << keyHex.data() << std::endl;
    std::cout << "IV:" << ivHex.data() << std::endl;
    
    std::cout << "'" << public_key << "'" << std::endl;
    std::string aesEncryptB64 = EncryptAESWithRSA(public_key, keyHex);

    //std::cout << "encrypt = " << aesEncryptB64 << std::endl;
}
