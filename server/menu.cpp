#include "server.hpp"

Command GetCommand(std::string command) 
{
    if (command == CREATE_COMMAND) return CREATE;
    if (command == JOIN_COMMAND) return JOIN;
    if (command == LIST_COMMAND) return LIST;
    if (command == LEAVE_COMMAND) return LEAVE;
    if (command == NEW_RSA_COMMAND) return NEW_RSA;
    return INVALID;
}

void    Server::CreateChatRoom(SSL *ssl) 
{
    std::vector<char> room_name(1024);

    SSL_write(ssl, INPUT_CHATROOM, strlen(INPUT_CHATROOM));
    int bytesRead = SSL_read(ssl, room_name.data(), room_name.size() - 1);
    
    // CHECK BYTE READ <= 0
    room_name[bytesRead - 1] = '\0';
    
    // CHECK IF CHANNEL IS OKEY
    this->_chatroom.push_back(Room(room_name.data(), GetUserWithSSL(ssl)));
}

void    Server::ListChatRoom(SSL *ssl) 
{
    for (int i = 0; i < (int)this->_chatroom.size(); i++) {
        SSL_write(ssl, this->_chatroom[i].GetName().c_str(), this->_chatroom[i].GetName().size());
    }
}

void    Server::JoinChatRoom(SSL *ssl) 
{

}

void    Server::Menu(Command cmd, SSL *ssl) 
{
    switch (cmd) {
        case CREATE:
            CreateChatRoom(ssl);
            std::cout << "Creating a new chat room..." << std::endl;
            break;
        case JOIN:
            std::cout << "Joining a chat room..." << std::endl;
            break;
        case LIST:
            ListChatRoom(ssl);
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