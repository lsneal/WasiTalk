#include "client.hpp"

std::mutex sendMutex;

void    ReceivMsg(SSL* _ssl)
{
    std::vector<char>   buffer(4096);
    int                 bytes_read = 0;

    while (true) 
    {
        bytes_read = SSL_read(_ssl, buffer.data(), buffer.size());
        if (bytes_read > 0) 
        {
            // Decrypt message and print
            std::lock_guard<std::mutex> lock(sendMutex);
            std::cout << buffer.data() << std::endl;
            OPENSSL_cleanse(buffer.data(), buffer.size());
        } 
        else
        {
            std::cout << "ERROR" << std::endl;
            return ;
        }
    }
}

void    SendMsg(SSL* _ssl)
{
    std::string user_input;
    
    while (true) 
    {
        std::getline(std::cin, user_input);
        std::lock_guard<std::mutex> lock(sendMutex);
        SSL_write(_ssl, user_input.c_str(), user_input.length());
        OPENSSL_cleanse(&user_input[0], user_input.size());
    }
}

bool     CheckBytesRead(int bytes_read, std::string message) 
{
    if (bytes_read > 0)
        std::cout << message << std::endl;
    else if (bytes_read == 0) 
    {
        std::cerr << "Connection close" << std::endl;
        return false;
    }
    else
    {
        std::cerr << "Error read messages" << std::endl;
        return false;
    }
    return true;
}


int    Client::StartCommunicationWithServer(std::vector<char> buffer) 
{
    std::string         user_input;

    // Receive server message for pseudo
    buffer.assign(buffer.size(), 0);
    int bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());
    
    if (CheckBytesRead(bytes_read, buffer.data()) == false)
        return -1;
    
    // Write pseudo
    std::getline(std::cin, user_input);
    SSL_write(this->_ssl, user_input.c_str(), user_input.length());

    // Send publickey RSA
    buffer.assign(buffer.size(), 0);
    SSL_write(this->_ssl, this->_publicKey.c_str(), this->_publicKey.length() - 1);

    // Read server message pseudo list
    buffer.assign(buffer.size(), 0);
    std::cout << "List of user connected: \n" << std::endl;
    bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());

    if (CheckBytesRead(bytes_read, buffer.data()) == false)
        return -1;

    // Enter pseudo list for communicate or send code for solo user
    std::string serv = "Solo on server";
    if (serv.compare(buffer.data()) != 0) 
    {
        std::cout << "" << std::endl;
        std::getline(std::cin, user_input);
        this->_pseudoSession = user_input;
        SSL_write(this->_ssl, user_input.c_str(), user_input.length());
    
        // receive rsa key
        bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());
        EncryptAndSendAES(this->_publicKey);

        return 1;
    }
    SSL_write(this->_ssl, this->_publicKey.c_str(), this->_publicKey.length());
    
    // Read for receive aes key session
    bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());

    this->_pseudoSession = extractPseudo(buffer.data());
    this->_aes = extractAndDecodeBase64(buffer.data(), this->_pseudoSession);

    bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());
    this->_iv = extractAndDecodeBase64(buffer.data(), this->_pseudoSession);

    std::cout << "aes = " << "'" << this->_aes << "'" << std::endl;
    std::cout << "iv = " << "'" << this->_iv << "'" << std::endl;

    return 1;
}

EVP_PKEY* loadPrivateKeyFromString(const std::string  &pemKey)
{
    BIO* bio = BIO_new_mem_buf(pemKey.data(), static_cast<int>(pemKey.size()));
    if (!bio) {
        std::cerr << "Error create bio" << std::endl;
        return NULL;
    }

    // Load key
    EVP_PKEY* rsaPrivateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!rsaPrivateKey) {
        std::cerr << "Error loading private key" << std::endl;
        return NULL;
    }

    BIO_free(bio);

    return rsaPrivateKey;
}

void Client::CommunicateWithServer()
{
    std::vector<char>   buffer(1024);

    //OPENSSL_cleanse(buffer, sizeof(buffer));
    if (StartCommunicationWithServer(buffer) == -1)
        return ;

    // Convert pem private key on RSA object for multithreading
    EVP_PKEY* privateKey = loadPrivateKeyFromString(this->_privateKey);

    // std::thread ReceivMsgThread1(ReceivMsg, this->_ssl, privatekey, this->_aes, this->_iv);
    
    std::thread ReceivMsgThread1(ReceivMsg, this->_ssl);
    std::thread SendMsgThread1(SendMsg, this->_ssl);

    ReceivMsgThread1.join();
    SendMsgThread1.join();
    
}