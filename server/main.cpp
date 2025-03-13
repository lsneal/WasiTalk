#include "server.hpp"
#include <mutex>

int createServerSocket(int port) 
{

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        ERROR_MSG("bind socket");
        close(serverSocket);
        return -1;
    }

    if (listen(serverSocket, 5) < 0) {
        ERROR_MSG("listen socket");
        close(serverSocket);
        return -1;
    }
    SERVER_LISTEN(port);

    return serverSocket;
}

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
            this->_tempSSL = ssl;
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
                
                if (PseudoIsOkey(buf.data()) == true) {
                    buf[bytesRead - 1] = '\0';
                    break ;
                }
                SSL_write(ssl, PSEUDO_USED, strlen(PSEUDO_USED));
            }
            
            // add fd new client
            FD_SET(clientSocket, &read_fds);
            max_fd = std::max(max_fd, clientSocket);
            this->client.push_back(Info(clientSocket, buf.data(), ssl));

            NEW_CLIENT(inet_ntoa(clientAddress.sin_addr), clientSocket)
        
        }
        ManageClientConnected(read_fds, copy_fds, this->_tempSSL);

        // client connected

    }
}

Command GetCommand(std::string command) 
{
    if (command == CREATE_COMMAND) return CREATE;
    if (command == JOIN_COMMAND) return JOIN;
    if (command == LIST_COMMAND) return LIST;
    if (command == LEAVE_COMMAND) return LEAVE;
    if (command == NEW_RSA_COMMAND) return NEW_RSA;
    return INVALID;
}

void    Server::Menu(Command cmd) 
{
    switch (cmd) {
        case CREATE:
            std::cout << "Creating a new chat room..." << std::endl;
            break;
        case JOIN:
            std::cout << "Joining a chat room..." << std::endl;
            break;
        case LIST:
            std::cout << "Listing available chat rooms..." << std::endl;
            break;
        case LEAVE:
            std::cout << "Leaving the chat room..." << std::endl;
            break;
        case NEW_RSA:
            std::cout << "Generating a new RSA key pair..." << std::endl;
            break;
        case INVALID:
        default:
            std::cerr << "Invalid command received!" << std::endl;
            break;
    }
}

void    Server::ManageClientConnected(fd_set &read_fds, fd_set &copy_fds, SSL *ssl) 
{
    for (int i = 0; i < GetClientSize(); i++) 
    {
        int clientSocket = this->client[i].getFd();
        if (FD_ISSET(clientSocket, &copy_fds)) 
        {
            char buffer[1024];
            int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
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
                buffer[bytesRead - 1] = '\0';
                std::cout << "Message from client " << clientSocket << ": " << buffer << std::endl;
                

                Command cmd = GetCommand(std::string(buffer));

                Menu(cmd);
                /*
                
                MENU:

                - create <name> --> create chat
                - join <name> --> join chat 

                - list --> list chat open
                - leave --> leave chat 
                
                - newrsa --> gen new key pair

                */

                // Exemple
                /*for (const auto& pair : clientSSLs) {
                    if (pair.first != clientSocket) {
                        SSL_write(pair.second, buffer, strlen(buffer));
                    }
                }*/
            }
        }
    }
}

int main(int argc, char **argv) 
{
    if (argc != 2)
        return 1;

    std::string buffer;

    memset((char *)buffer.c_str(), 0, sizeof(buffer.c_str()));

    int     port = atoi(argv[1]);
    Server  Server(port);

    InitOpenSSL();
    const SSL_METHOD    *method = SSLv23_server_method();
    Server.SetMethodSSL(method);

    // load cert and privatekey
    if (Server.LoadCertAndPrivateKey() == -1)
        return 1;

    /*  INIT TCP SOCKET */
    int serverSocket = createServerSocket(port);

    Server.StartServer(serverSocket);

    close(serverSocket);

    SSL_CTX_free(Server.GetContextSSL());
    EVP_cleanup();

    return 0;
}