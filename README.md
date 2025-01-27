## Description

This C++ project implements a server and a client that communicate via sockets. The main feature implemented so far is session management using threads to handle multiple simultaneous connections. The project also utilizes the OpenSSL library to add SSL/TLS support, ensuring secure communication between the server and the client.

Key features of the project include:
- Secure communication using SSL/TLS via the OpenSSL library.
- End-to-End Encryption (E2EE) of messages with RSA and AES, ensuring that only authorized parties can decrypt and read the messages.
- Multi-connection handling using threads, allowing the server to handle multiple clients in parallel without blocking.

## Current Features

- **Server:**
  - Handles multiple client connections simultaneously by creating a new thread for each client.
  - Utilizes SSL/TLS to secure each connection and ensure the confidentiality of the exchanged data.
  - Implements encryption and decryption of messages using RSA and AES for secure communication.
  - Optimized session management to ensure high performance even with many simultaneous clients.

- **Client:**
  - Connects to the server via SSL/TLS, ensuring a secure connection.
  - Sends and receives messages securely through E2EE with RSA and AES.
  - Simple user interface allowing users to input messages to send to the server.

- **End-to-End Encryption (E2EE):**
  - **RSA**: Used for securely exchanging asymmetric keys (public/private key pair).
  - **AES**: Used for symmetric encryption of the data once the key is securely shared via RSA.

## Known Issues

  - The code still contains several bugs that need to be fixed.
  - There are issues with thread synchronization and resource management, causing occasional crashes when handling multiple connections.
  - Some SSL/TLS handshake errors may occur, leading to connection failures in certain cases.

These issues are being actively worked on and will be fixed in future updates.