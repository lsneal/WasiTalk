#include "client.hpp"

void    Client::EncryptAndSendAES(std::string public_key)
{
    std::vector<unsigned char> key(64);
    std::vector<unsigned char> keyHex(64);
    std::vector<unsigned char> iv(32);
    std::vector<unsigned char> ivHex(32);
    std::vector<unsigned char> aesBinaryKey;
    std::string aesEncryptB64;

    generateAESKeyAndIV(key, iv);
    convertToHex(key, keyHex); // KEY
    convertToHex(iv, ivHex); // IV 
    
    aesEncryptB64 = EncryptAESWithRSA(public_key, keyHex);

    std::cout << "encrypt = " << aesEncryptB64 << std::endl;
}
