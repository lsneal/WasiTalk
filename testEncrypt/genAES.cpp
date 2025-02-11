#include "test.hpp"

void    generateAESKeyAndIV(std::vector<unsigned char> &key, std::vector<unsigned char> &iv)
{
    /*
        Generate Key --> 256 bits
    */
    std::cout << AES_BLOCK_SIZE << std::endl;
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