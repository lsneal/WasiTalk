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