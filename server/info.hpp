#ifndef INFO_H
#define INFO_H

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

class Info {

    public:
        Info(int fd, std::string pseudo, SSL *ssl): _fd(fd), _pseudo(pseudo), _sslSession(ssl) {}
        ~Info() {}

        void    setPseudo(std::string pseudo) { _pseudo = pseudo; }
        void    setPemKey(std::string pem){ _pemKey = pem; }
        void    setFd(int fd) { _fd = fd; }
        void    setSSL(SSL *sslSession) { _sslSession = sslSession; }
    
        std::string getPseudo() { return _pseudo; }
        std::string getPemKey() { return _pemKey; }
        int         getFd() { return _fd; }
        SSL         *getSSL() { return _sslSession; }
        fd_set      getReadFd() { return _read_fds; }
    private:
        int         _fd;
        std::string _pseudo;
        std::string _pemKey;
        SSL         *_sslSession;
        fd_set      _read_fds;

};

#endif