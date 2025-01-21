#include "client.hpp"


std::string ConvertKeyOnStrings(BIO *bio) 
{
    char    *keyBuffer;
    size_t  keyLength = BIO_pending(bio);

    keyBuffer = (char *)malloc(sizeof(char *) + (keyLength + 1));
    
    BIO_read(bio, keyBuffer, (int)keyLength);
    keyBuffer[keyLength] = '\0';

    std::string keyString(keyBuffer);
    free(keyBuffer);
    
    return keyString;
}

bool generateRSAKeys(std::string &publicKey, std::string &privateKey) 
{
    int             keySize = 4096;
    EVP_PKEY_CTX    *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx) {
        std::cerr << "Error context creation" << std::endl;
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error init context for RSA key" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // INit size RSA key
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize) <= 0) {
        std::cerr << "Error init RSA key size" << std::endl;
        return false;
    }

    // Gen pair RSA key
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error gen key pair" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;

    }

    // Save public key PEM format
    BIO *bioPublic = BIO_new(BIO_s_mem()); // Bio_new --> write key on memory space
    if (!PEM_write_bio_PUBKEY(bioPublic, pkey)) // to PEM format 
    {
        std::cerr << "Error write public key" << std::endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // Save private key PEM format
    BIO *bioPrivate = BIO_new(BIO_s_mem());
    
    /*
        PKCS #8 is standard syntax for private key
        PEM_write_bio_PKCS8PrivateKey() --> convert on syntax PKCS #8
    */
    if (!PEM_write_bio_PKCS8PrivateKey(bioPrivate, pkey, NULL, NULL, 0, NULL, NULL))
    {
        std::cerr << "Error write private key" << std::endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // convert public key on strings
    publicKey = ConvertKeyOnStrings(bioPublic);

    privateKey = ConvertKeyOnStrings(bioPrivate);
    
    BIO_free_all(bioPublic);
    BIO_free_all(bioPrivate);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return true;
}