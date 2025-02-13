#include "test.hpp"

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

int main(void)
{
    std::string publick, privatek;
    generateRSAKeys(publick, privatek);
    //std::cout << publick << std::endl;

    std::vector<unsigned char> key(64);
    std::vector<unsigned char> keyHex(64);
    std::vector<unsigned char> iv(32);
    std::vector<unsigned char> ivHex(32);
    generateAESKeyAndIV(key, iv);

    //std::cout << key.data() << std::endl;

    convertToHex(key, keyHex);
    std::cout << "'" << keyHex.data() << "'" << std::endl;

    //convertToHex(iv, ivHex);
    //std::cout << "'" << ivHex.data() << "'" << std::endl;

    std::string aesEncryptB64 = EncryptMessagesWithRSA(publick, keyHex);
    
    std::cout << "AES key encrypt --> " << "'" << aesEncryptB64  << "'" << std::endl;
    
    std::vector<unsigned char> aesBinaryKey = base64_decode(aesEncryptB64);

    std::string decrypt =  DecryptMessagesWithRSA(privatek, aesBinaryKey);

    std::cout << decrypt << std::endl;
    // convert aesEncrypt to binary 
    // decrypt binary
    // convert aes to binary for encrypt msg

    // for decrypt ---> convert hex to binary data

    return 1;
}
