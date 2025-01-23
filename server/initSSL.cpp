#include "server.hpp"

void InitOpenSSL() 
{
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
}

void    Server::SetMethodSSL(const SSL_METHOD *method) 
{ 
    this->_ctx = SSL_CTX_new(method); 
};

int     Server::LoadCertAndPrivateKey() 
{
    if (SSL_CTX_use_certificate_file(this->_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 || 
        SSL_CTX_use_PrivateKey_file(this->_ctx, KEY_SSL, SSL_FILETYPE_PEM) <= 0) 
    {
        std::cerr << "Error load cert or private key" << std::endl;
        return -1;
    }
    return 1;
};