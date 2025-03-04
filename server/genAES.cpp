#include "server.hpp"

void    generateAESKeyAndIV(std::vector<unsigned char> &key, std::vector<unsigned char> &iv);

std::string string_to_hex(const std::string &input)
{
    static const char hex_digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

void    Server::sendAESKeyForSession(SSL *ssl, SSL *ssl_session)
{
    (void)ssl;
    (void)ssl_session;
    //std::vector<unsigned char>  key(AES_BLOCK_SIZE * 2);
    //std::vector<unsigned char>  iv(AES_BLOCK_SIZE);

    //generateAESKeyAndIV(key, iv);

    //std::string PEM1 = GetPEMwithSSL(ssl);
    //std::string PEM2 = GetPEMwithSSL(ssl_session);

    ///unsigned char   *firstKey = EncryptMessagesWithRSA(PEM1, key, ssl, ssl_session);
    ///unsigned char   *firstIV = EncryptMessagesWithRSA(PEM1, iv, ssl, ssl_session);

    //std::string firstKey =  EncryptMessagesWithRSA(PEM1, key);
    //std::string firstIV =  EncryptMessagesWithRSA(PEM1, key);

    //std::string KeyAndIV = firstKey + " : " + firstIV;

    //std::cout << "GENERATE AND SEND AES KEY" << std::endl;

    //SSL_write(ssl, KeyAndIV.c_str(), KeyAndIV.size());
    //SSL_write(ssl, firstIV.c_str(), firstIV.size());
    ///sleep(1);
    ///key1 = true;

    //std::string secondKey =  EncryptMessagesWithRSA(PEM2, key);
    //std::string secondIV =  EncryptMessagesWithRSA(PEM2, key);

    //KeyAndIV = secondKey + " : " + secondIV;

   // SSL_write(ssl_session,  KeyAndIV.c_str(), KeyAndIV.size());
    //SSL_write(ssl_session, secondIV.c_str(), secondIV.size());

    //unsigned char *secondKey = EncryptMessagesWithRSA(PEM2, key);
    //unsigned char *secondIV = EncryptMessagesWithRSA(PEM2, iv);
//
    //SSL_write(ssl_session, secondKey, sizeof(secondKey));
    //SSL_write(ssl_session, secondIV, sizeof(secondIV));
    //sleep(1);
    //key2 = true;

}


void    generateAESKeyAndIV(std::vector<unsigned char> &key, std::vector<unsigned char> &iv)
{
    /*
        Generate Key --> 256 bits
    */
    if (RAND_bytes(key.data(), AES_BLOCK_SIZE * 2) != 1) {
        std::cerr << "Error: generation AES key" << std::endl;
        return ;
    }
    
    /*
        Generate IV --> 128 bits
    */
    if (RAND_bytes(iv.data(), AES_BLOCK_SIZE) != 1) {
        std::cerr << "Error: generation initialization vector" << std::endl;
        return ;
    }

    //std::cout << "KEY: " << string_to_hex(key.data()) << std::endl; 
    //std::cout << "IV: " << string_to_hex(iv.data()) << std::endl; 
}