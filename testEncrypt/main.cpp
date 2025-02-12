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
    std::cout << hex_string << std::endl;
    // Resize the output vector to fit the hex string
    hex_data.resize(hex_string.size());

    // Copy the hex string to the output vector
    std::copy(hex_string.begin(), hex_string.end(), hex_data.begin());
}


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


int main(void)
{
    std::string publick, privatek;
    generateRSAKeys(publick, privatek);
    std::cout << publick << std::endl;

    std::vector<unsigned char> key(64);
    std::vector<unsigned char> keyHex(64);
    std::vector<unsigned char> iv(32);
    std::vector<unsigned char> ivHex(32);
    generateAESKeyAndIV(key, iv);

    convertToHex(key, keyHex);
    std::cout << "'" << keyHex.data() << "'" << std::endl;

    convertToHex(iv, ivHex);
    std::cout << "'" << ivHex.data() << "'" << std::endl;

    std::string aes = EncryptMessagesWithRSA(publick, keyHex);
    std::cout << "AES key encrypt --> " << aes << std::endl;

    return 1;
}