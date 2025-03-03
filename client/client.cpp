#include "client.hpp"

bool Client::connectToServer() 
{
    int _clientFd = socket(AF_INET, SOCK_STREAM, 0);
    if (_clientFd == -1) {
        std::cerr << "Erreur socket creation" << std::endl;
        return false;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(_serverPort);
    if (inet_pton(AF_INET, _serverIp.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Ip invalid" << std::endl;
        return false;
    }

    if (connect(_clientFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error connection server" << std::endl;
        return false;
    }

    this->_ssl = SSL_new(this->_ctx);
    if (!this->_ssl) {
        std::cerr << "Error obj ssl" << std::endl;
        return false;
    }

    SSL_set_fd(this->_ssl, _clientFd);
    if (SSL_connect(this->_ssl) != 1) {
        std::cerr << "Error ssl connect" << std::endl;
        return false;
    }

    std::cout << "Connected: " << _serverIp << ":" << _serverPort << std::endl;
    return true;
}

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
        SSL_write(this->_ssl, user_input.c_str(), user_input.length());
    
        // generate aes and iv
        std::string aes = "aes key";

        // receive rsa key
        bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());
        std::cout << "RSA key receive" << std::endl;

        //std::cout << "RSA: " << buffer.data() << std::endl;
        //std::string public_key(buffer.begin(), buffer.end());
        
        //std::string public_key = buffer.data();
        //std::string pbk = extractPublicKey(public_key);
        std::string PEM = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAm+tm83RVw298sxcq+7fW\nAjshuVjEGc1dGEtfSUQbYqPF5MgOusz3AWENcDgCHJabtEBiOG14nkpGfCmgxcqf\nNoDOVBAqM+h4znjk3uK6uS1wVdlKSpJh1HPvnijDlLiQ6BrMYJn9DJKN7xV4v2gO\nzEav7hTjIGvu77BUnCQ5RXRKK/ZPJ9hceaDzpti6OGUg7YQG5TlZnY/7CznxcpKA\nzcafAMjRpfhUB452rWoMqeHLjWWSfdOXjodU06eUF49dEamo/uDPsJ33Y8W3TF4Q\no1wjwcmr14R/qmrYY1D3L0J3I1ZvFrkoWbCvsF/9oEE7XjbMWy+C6SGxF1gljB/p\noTjDkXYGxCxzbJPcvUoABAkhYcmR79D/MXt3GXDUy35TIlwWw5fxz+e2Uz36W1c1\nad05vrxUTVDZcEFRvwe2Y2gVk83uD0NHR/IPc5zwkNLw/N0DDr3Dj+P20MpsHlkR\nZmnPTcIigLF/9ktcdbUaeajo25aC8c1s0JL2ej/OrEM45ip3OnbV0R6woKoKgez8\nAtg7PWjj6sgN3sob9bPYqdV9DqnybMwLrjwoNJgNqdbtBU19p/pnB6y2jB4CvvG6\ngA5G3nOhV/AgF0goGeMRgxBIqc022f92jzA64sZ+22mwXA2mSkeZETYDk0x6QIJ6\n0r8syqZaf8N+OYxo/mQiKjUCAwEAAQ==\n-----END PUBLIC KEY-----";
        std::vector<unsigned char> key(64);
        std::vector<unsigned char> keyHex(64);
        std::vector<unsigned char> iv(32);
        std::vector<unsigned char> ivHex(32);
        key[0] = 'B';
    
        //generateAESKeyAndIV(key, iv);
        //convertToHex(key, keyHex); // KEY
        //convertToHex(iv, ivHex);
        
        std::string aesEncryptB64 = EncryptAESWithRSA(PEM, key);

        //EncryptAndSendAES(this->_publicKey);

        // encrypt aes and iv with rsa
        // send message at server 
        return 1;
    }
    std::cout << "YOOOOO" << std::endl;
    SSL_write(this->_ssl, this->_publicKey.c_str(), this->_publicKey.length());
    return 1;
}

int    Client::InitCommunicationWithRSA(std::vector<char> buffer) 
{
    buffer.assign(buffer.size(), 0);
    
    int bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());
    //if (CheckBytesRead(bytes_read, buffer.data()) == false)
    //    return -1;
    
    std::string ivkey = buffer.data();

    std::cout << "Key: " << "'" << ivkey << "'" << std::endl;
    
    // receive AES key
    // decrypt message with privateKey
    // save AES key
    return 0 ;
}

void Client::CommunicateWithServer()
{
    std::vector<char>   buffer(1024);

    //OPENSSL_cleanse(buffer, sizeof(buffer));
    if (StartCommunicationWithServer(buffer) == -1)
        return ;

//    if (InitCommunicationWithRSA(buffer) == -1)
//        return ;

    std::thread ReceivMsgThread1(ReceivMsg, this->_ssl);
    std::thread SendMsgThread1(SendMsg, this->_ssl);

    ReceivMsgThread1.join();
    SendMsgThread1.join();
    
}