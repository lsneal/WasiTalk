#include "client.hpp"

std::string extractPublicKey(std::string &text)
{
    const std::string beginMarker = "-----BEGIN PUBLIC KEY-----";
    const std::string endMarker = "-----END PUBLIC KEY-----";

    size_t beginPos = text.find(beginMarker);
    size_t endPos = text.find(endMarker, beginPos);

    if (beginPos == std::string::npos || endPos == std::string::npos) {
        throw std::runtime_error("Public key not found");
    }

    beginPos += beginMarker.length();
    std::string publicKey = text.substr(beginPos, endPos - beginPos);

    return beginMarker + publicKey + endMarker;
}

std::string extractPseudo(const std::string& input)
{
    size_t pos = input.find(":");
    if (pos == std::string::npos) {
        throw std::invalid_argument("Error find :");
    }
    return input.substr(0, pos);
}

std::string extractAndDecodeBase64(const std::string &input, const std::string &pseudo)
{
    size_t pos = input.find(pseudo + ":");
    if (pos == std::string::npos) {
        throw std::invalid_argument("Pseudo not found");
    }
    std::string strbase64 = input.substr(pos + pseudo.length() + 2);

    return strbase64;
}