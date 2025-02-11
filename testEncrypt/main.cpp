#include "test.hpp"

std::string convertToHex(std::vector<unsigned char> data)
{
    std::stringstream ss;

    size_t last_non_zero = data.size() - 1;
    while (last_non_zero > 0 && data[last_non_zero] == 0) {
        last_non_zero--;
    }

    for (size_t i = 0; i <= last_non_zero; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    
    return ss.str();
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

    std::vector<unsigned char> key(1024);
    std::vector<unsigned char> iv(1024);
    generateAESKeyAndIV(key, iv);

    std::string keyhex = convertToHex(key);
    std::cout << "'" << keyhex << "'" << std::endl;

    //std::string ivhex = convertToHex(iv);
    //std::cout << "'" << ivhex << "'" << std::endl;


    return 1;
}