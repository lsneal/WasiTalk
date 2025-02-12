#ifndef TEST_HPP
#define TEST_HPP

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <netinet/in.h>
#include <unordered_map>
#include <string>
#include <iostream>
#include <unistd.h>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <iomanip>

void convertToHex(std::vector<unsigned char> &data, std::vector<unsigned char> &hex_data);
std::string string_to_hex(const std::string &input);
bool generateRSAKeys(std::string &publicKey, std::string &privateKey);
std::string ConvertKeyOnStrings(BIO *bio);
void    generateAESKeyAndIV(std::vector<unsigned char> &key, std::vector<unsigned char> &iv);
std::string DecryptMessagesWithRSA(std::string PEM, const std::string encrypted);
std::string EncryptMessagesWithRSA(std::string PEM, std::vector<unsigned char> message);    
#endif
