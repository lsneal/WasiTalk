## Description

This C++ project implements a server and a client that communicate via sockets. The main feature implemented so far is session management using threads to handle multiple simultaneous connections. The project also utilizes the OpenSSL library to add SSL/TLS support, ensuring secure communication between the server and the client.

### Current Features
- **Server**:
  - Handles multiple client connections simultaneously using threads.
  - Each connection uses an SSL/TLS session to secure communication.
  
- **Client**:
  - Connects to the server via SSL/TLS.
  - Sends and receives data over a secure connection.

### Technologies Used
- **C++**: The primary programming language used for the development of the project.
- **OpenSSL**: Library used to implement SSL/TLS support to secure communications between the server and the client.
- **C++ Threads**: Concurrency management using the C++ Standard Library to allow the server to handle multiple connections simultaneously.