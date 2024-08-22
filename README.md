### Post-Quantum Adaptation of Signal
## Overview
This project is part of my master’s thesis, focusing on adapting the Signal protocol to be secure against quantum computing attacks. The goal is to integrate post-quantum cryptographic algorithms into the Signal protocol to ensure its long-term security. \
It constitutes a proof of concept: key mechanisms of Signal have been implemented with FrodoKEM and FrodoKEX+. \
This code consist of a client-server application. Clients send custom bytes to the server, which processes them, either by storing or retrieving data from a database. End-to-end encryption is achieved.

## Installation
To setup the project, please follow these steps:
1. Clone the repository: 
```bash
    git clone https://github.com/maedekey/post-quantum-adaptation-of-signal.git
    cd post-quantum-adaptation-of-signal
```
2. Install dependencies: 
* For database management:
```bash
    >pip install psycopg2
```
* For AES encryption:
```bash
    >pip install pycryptodome
    >pip install pycryptodomex
```
* For pre-quantum ECDSA signatures:
```bash
    >pip install ecdsa
```
* For FrodoKEM dependencies:
```bash
    >pip install bitstring
    >pip install cryptography
```
3. Setup database:
Go to the server directory:
```bash
    >cd /server
```
* open createDB.py and resetdb.py and change username and password to your own postgres username and password
* execute:
```bash
    >python3 createDB.py
```

note: if you are launching this project from an IDE, mark the dilithium directory as a Source Root Directory.
## Launch the project:
```bash
    >python3 server.py
    >cd ..
    >cd /client
    >python3 main.py
```
This project is meant to be executed in a terminal, in command line only. 

