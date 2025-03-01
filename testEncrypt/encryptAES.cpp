#include "test.hpp"

std::string EncryptAESWithRSA(std::string PEM, std::vector<unsigned char> message) 
{

    /*
        Load PublicKey with PEM format
        BIO *BIO_new_mem_buf(const void *buf, int len);
    */
    BIO* bio = BIO_new_mem_buf(PEM.c_str(), -1);
    if (!bio) {
        std::cerr << "Error: load PEM" << std::endl;
        return NULL;
    }

    /*
        Read PublicKey with object bio
        EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x,
                                       pem_password_cb *cb, void *u);
    */
    EVP_PKEY* public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!public_key) {
        std::cerr << "Error: read PEM" << std::endl;
        return NULL;
    }

    /*
        Create context for cypher
        EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
    */
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx) {
        std::cerr << "Error: context create" << std::endl;
        return NULL;
    }

    /*
        Init context for cypher with OAEP (Optimal asymmetric encryption padding)
        int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
    */
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        std::cerr << "Error: init cypher" << std::endl;
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "Error: padding configuration" << std::endl;
        return NULL;
    }

    // convert binary to hexa for encrypt 
    std::vector<unsigned char> messageHex(64);
    convertToHex(message, messageHex);

    size_t encrypted_size;
    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_size, \
                            (unsigned char *)message.data(), message.size()) <= 0)
    {
        std::cerr << "Error: get size for encrypt" << std::endl;
        return NULL;
    }

    std::vector<unsigned char> encrypted(encrypted_size);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &encrypted_size, \
                            (unsigned char *)message.data(), message.size()) <= 0)
    {
        std::cerr << "Error: encrypt message" << std::endl;
        return NULL;
    }
    //std::cout << "Encrypted data: " <<  "'" << encrypted.data() << "'" << std::endl;
    //std::string hex = string_to_hex((const char *)encrypted.data());
    //std::cout << "'" << hex << "'" << std::endl;
    std::string hex = base64_encode(encrypted);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    BIO_free(bio);

    //return encrypted.data();
    return hex;
}