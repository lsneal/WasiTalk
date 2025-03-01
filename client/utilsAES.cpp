#include "client.hpp"

void    generateAESKeyAndIV(std::vector<unsigned char> &key, std::vector<unsigned char> &iv)
{
    /*
        Generate Key --> 256 bits
    */
    if (RAND_bytes(key.data(), AES_BLOCK_SIZE * 4) != 1) {
        std::cerr << "Error: generation AES key" << std::endl;
        return ;
    }
    
    /*
        Generate IV --> 128 bits
    */
    if (RAND_bytes(iv.data(), AES_BLOCK_SIZE * 2) != 1) {
        std::cerr << "Error: generation initialization vector" << std::endl;
        return ;
    }

    //std::cout << "KEY: " << string_to_hex(key.data()) << std::endl; 
    //std::cout << "IV: " << string_to_hex(iv.data()) << std::endl; 
}

void convertToHex(std::vector<unsigned char>& data, std::vector<unsigned char> &hex_data)
{
    std::stringstream ss;

    // Convert each byte to its hexadecimal representation
    for (size_t i = 0; i < data.size(); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }

    // Get the hex string from the stringstream
    std::string hex_string = ss.str();
    //std::cout << hex_string << std::endl;
    // Resize the output vector to fit the hex string
    hex_data.resize(hex_string.size());

    // Copy the hex string to the output vector
    std::copy(hex_string.begin(), hex_string.end(), hex_data.begin());
}

std::string base64_encode(std::vector<unsigned char> data)
{
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());

    bio = BIO_push(b64, bio);

    BIO_write(bio, data.data(), data.size());

    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string base64_str(buffer_ptr->data, buffer_ptr->length);

    BIO_free_all(bio);

    return base64_str;
}

std::vector<unsigned char> base64_decode(const std::string& encoded_string)
{
    BIO *bio, *b64;
    int decode_len = encoded_string.size() * 3 / 4;
    std::vector<unsigned char> decoded_data(decode_len);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded_string.data(), encoded_string.size());

    bio = BIO_push(b64, bio);

    decode_len = BIO_read(bio, decoded_data.data(), encoded_string.size());

    decoded_data.resize(decode_len);
    BIO_free_all(bio);

    return decoded_data;
}
