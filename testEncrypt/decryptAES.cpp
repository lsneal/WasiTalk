#include "test.hpp"

std::string DecryptAESWithRSA(std::string PEM, std::vector<unsigned char> encrypted)
{
    /*
        Load PrivateKey with PEM format
        BIO *BIO_new_mem_buf(const void *buf, int len);
    */
    BIO* bio = BIO_new_mem_buf(PEM.c_str(), -1);
    if (!bio) {
        std::cerr << "Error: load PEM" << std::endl;
        return "";
    }

    /*
        Read PrivateKey with object bio
        EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
                                         pem_password_cb *cb, void *u);
    */
    EVP_PKEY* private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!private_key) {
        std::cerr << "Error: read PEM" << std::endl;
        BIO_free(bio);
        return "";
    }

    /*
        Create context for decryption
        EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
    */
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) {
        std::cerr << "Error: context create" << std::endl;
        EVP_PKEY_free(private_key);
        BIO_free(bio);
        return "";
    }

    /*
        Initialize context for decryption with OAEP
        int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
    */
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        std::cerr << "Error: init cypher" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        BIO_free(bio);
        return "";
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "Error: padding configuration" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        BIO_free(bio);
        return "";
    }

    // Get size 
    size_t decrypted_size;
    if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_size, (unsigned char *)encrypted.data(), encrypted.size()) <= 0) {
        std::cerr << "Error: get size for decrypt" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        BIO_free(bio);
        return "";
    }
    
    // Decrypt the message
    std::vector<unsigned char> decrypted(decrypted_size);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &decrypted_size, (unsigned char *)encrypted.data(), encrypted.size()) <= 0) {
        std::cerr << "Error: decrypt message" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        BIO_free(bio);
        return "";
    }

    // Convert the result back to a string
    std::string decrypted_message(decrypted.begin(), decrypted.end());

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    BIO_free(bio);

    return decrypted_message;
}
