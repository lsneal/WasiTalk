#include "server.hpp"

void    Server::StartServer(int serverSocket)
{
    sockaddr_in clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    fd_set read_fds;
    
    // init fd
    FD_ZERO(&read_fds);
    FD_SET(serverSocket, &read_fds);
    int max_fd = serverSocket;

    while (true) 
    {
        fd_set copy_fds = read_fds;
        int activity = select(max_fd + 1, &copy_fds, nullptr, nullptr, nullptr);

        if (activity < 0) {
            ERROR_MSG("SELECT FAILED");
            break ;
        }

        // if new client
        if (FD_ISSET(serverSocket, &copy_fds)) 
        {
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);
            if (clientSocket < 0) {
                ERROR_MSG("ACCEPT FAILED");
                continue ;
            }

            // config ssl new client
            SSL *ssl = SSL_new(this->_ctx);
            SSL_set_fd(ssl, clientSocket);
            if (SSL_accept(ssl) == -1) 
            {
                ERROR_MSG("SSL ACCEPT");
                close(clientSocket);
                SSL_free(ssl);
                continue ;
            }

            std::vector<char> buf(1024);
            while (1)
            {
                SSL_write(ssl, INPUT_PSEUDO, strlen(INPUT_PSEUDO));
                int bytesRead = SSL_read(ssl, buf.data(), buf.size() - 1);
                
                buf[bytesRead] = '\0';                
                if (PseudoIsOkey(buf.data()) == true) {
                    std::cout << "Pseudo: " << buf.data() << std::endl;
                    break ;
                }
                SSL_write(ssl, PSEUDO_USED, strlen(PSEUDO_USED));
            }
            
            // add fd new client
            FD_SET(clientSocket, &read_fds);
            max_fd = std::max(max_fd, clientSocket);
            
            // get RSA publickey
            std::vector<char> publicRSA(1024);
            SSL_read(ssl, publicRSA.data(), publicRSA.size() - 1);

            this->client.push_back(Info(clientSocket, buf.data(), ssl, publicRSA.data()));
            
            // if client.size() > 1 --> send publickey at all client
            distributePublicKeyToClients(ssl, publicRSA.data());

            NEW_CLIENT(inet_ntoa(clientAddress.sin_addr), clientSocket)
        
        }
        // client connected
        ManageClientConnected(read_fds, copy_fds);
    }
}

void    Server::distributePublicKeyToClients(SSL *ssl, std::string publicRSA) 
{
    if (this->client.size() == 1)
        return ;

    std::cout << "size: " << this->client.size() << std::endl;
    for (int i = 0; i < (int)this->client.size(); i++)
    {
        if (ssl != this->client[i].getSSL())
            SSL_write(this->client[i].getSSL(), publicRSA.c_str(), publicRSA.length());
    }
}


/*

    MENU:
            - create <name> --> create chat
            - join <name> --> join chat 
            - list --> list chat open
            - leave --> leave chat 
            - newrsa --> gen new key pair

*/

void parseMessage(const std::vector<char>& buffer, std::string& pseudo, std::string& msg)
{
    std::string fullMessage(buffer.begin(), buffer.end());

    size_t spacePos = fullMessage.find(' ');

    if (spacePos != std::string::npos) {
        pseudo = fullMessage.substr(0, spacePos);
        msg = fullMessage.substr(spacePos + 1);
    }
    else {
        pseudo = fullMessage;
        msg = "";
    }
}

void    Server::ManageClientConnected(fd_set &read_fds, fd_set &copy_fds) 
{
    for (int i = 0; i < GetClientSize(); i++) 
    {
        SSL *ssl = this->client[i].getSSL();
        int clientSocket = this->client[i].getFd();
        if (FD_ISSET(clientSocket, &copy_fds)) 
        {
            std::vector<char> buffer(1024);
            int bytesRead = SSL_read(ssl, buffer.data(), buffer.size() - 1);
            if (bytesRead <= 0)
            {
                // deconnection client
                if (bytesRead == 0) {
                    CLIENT_DISCONNECTED(clientSocket);
                } 
                else
                    ERROR_MSG("READING FROM CLIENT");

                // close connnection
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(clientSocket);
                FD_CLR(clientSocket, &read_fds);
            } 
            else
            {
                buffer[bytesRead] = '\0';
                std::cout << "Message from client " << clientSocket << ": " << buffer.data() << std::endl;
            
                std::string user;
                std::string msg;
                parseMessage(buffer, user, msg);
                std::cout << "msg:" << "'" << msg << "'" << std::endl;
                std::cout << "user:" << "'" << user << "'" << std::endl;
                SendMessage(ssl, user, msg);
                
                //Command cmd = GetCommand(std::string(buffer.data()));
                //Menu(cmd, ssl, msg);
            }
        }
    }
}