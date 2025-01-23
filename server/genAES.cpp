#include "server.hpp"

void    generateAESKeyAndIV(std::vector<unsigned char> &key, std::vector<unsigned char> &iv);

unsigned char    *EncryptMessagesWithRSA(std::string PEM, std::vector<unsigned char> message) 
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

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    BIO_free(bio);

    return encrypted.data();
}


void    Server::sendAESKeyForSession(SSL *ssl, SSL *ssl_session)
{

    std::vector<unsigned char>  key(AES_BLOCK_SIZE * 2);
    std::vector<unsigned char>  iv(AES_BLOCK_SIZE);

    generateAESKeyAndIV(key, iv);

    std::string PEM1 = GetPEMwithSSL(ssl);
    std::string PEM2 = GetPEMwithSSL(ssl_session);

    unsigned char   *firstKey = EncryptMessagesWithRSA(PEM1, key);
    unsigned char   *firstIV = EncryptMessagesWithRSA(PEM1, iv);

    SSL_write(ssl, firstKey, sizeof(firstKey));
    SSL_write(ssl, firstIV, sizeof(firstIV));
    
    unsigned char *secondKey = EncryptMessagesWithRSA(PEM2, key);
    unsigned char *secondIV = EncryptMessagesWithRSA(PEM2, iv);

    SSL_write(ssl_session, secondKey, sizeof(secondKey));
    SSL_write(ssl_session, secondIV, sizeof(secondIV));

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
}