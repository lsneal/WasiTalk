#include "client.hpp"

void    Client::EncryptAndSendAES(std::string public_key)
{
    std::vector<unsigned char> key(AES_BLOCK_SIZE * 4);
    std::vector<unsigned char> keyHex(64);
    std::vector<unsigned char> iv(AES_BLOCK_SIZE * 2);
    std::vector<unsigned char> ivHex(32);

    generateAESKeyAndIV(key, iv);
    convertToHex(key, keyHex); // KEY
    convertToHex(iv, ivHex); // IV 

    // Encrypt for user
    this->_aes = EncryptAESWithRSA(this->_publicKey, keyHex);
    this->_iv = EncryptAESWithRSA(this->_publicKey, ivHex);
    
    // Encrypt key and iv for session
    std::string aesKeyEncryptB64 = EncryptAESWithRSA(public_key, keyHex);
    std::string aesIvEncryptB64 = EncryptAESWithRSA(public_key, ivHex);

    SSL_write(this->_ssl, aesKeyEncryptB64.c_str(), aesKeyEncryptB64.length());
    SSL_write(this->_ssl, aesIvEncryptB64.c_str(), aesIvEncryptB64.length());

    //std::cout << "encrypt = " << aesEncryptB64 << std::endl;
}
