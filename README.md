# Distributed Encrypted-File-System (CMSC - 626 Fall 2023)

## Overview

This project implements a Distributed Encrypted File System with features such as a simple file system structure, support for multiple accesses, and role-based access control. The system employs various libraries and technologies to achieve its functionality.

## Features

- **Simple File System:**
  - Implements a straightforward file system structure for ease of use.

- **Multiple Access File System:**
  - Supports multiple access points, allowing concurrent interactions with the file system.

- **Role-Based Access:**
  - Implements role-based access control to manage permissions and security.

## Libraries Used

The project utilizes a variety of Python libraries to achieve its functionality:

- **sys, os:** Fundamental libraries for system-level operations.

- **threading, pickle:** Used for implementing multithreading and serialization.

- **socket, mysql.connector:** Enables networking capabilities and interaction with MySQL databases.

- **datetime, time:** Facilitates timestamp handling.

- **fcntl:** Provides file control options, essential for implementing file locking.

- **shutil, rsa, bcrypt:** Used for file operations, encryption, and password hashing.

- **hashlib:** Implements cryptographic hash functions.

- **getpass, getpass_asterisk:** Ensures secure password input.

- **base64, asn1, pkcs1, sha256:** Used for encoding and cryptographic functions.

- **Cryptography Hazmat Primitives:** Various modules from the `cryptography` library to implement cryptographic primitives.

## Usage

1. **Installation:**
   - Clone the repository to your local machine.

2. **Dependencies:**
   - Ensure you have Python installed.
   - Install the required dependencies using `pip install -r requirements.txt`.

3. **Configuration:**
   - Modify the configuration files as needed, such as database connection details.

4. **Run the System:**
   - Execute the main script to run the Distributed Encrypted File System.


## Execution Steps

Follow these steps to set up and run the Distributed Encrypted File System:

### 1. Database Setup
- **Using SQL Server:**
  - Run the `sql_queries.txt` script to initialize the database.
- **Database Verification:**
  - Ensure that the tables `users`, `transactions`, `files`, and `access control` are successfully created in the `pcsproj` database.

### 2. Environment Setup
- **IDE Setup:**
  - Open the project in your preferred IDE.
- **Install Libraries:**
  - Install all the required libraries by running `pip install -r requirements.txt`.

### 3. Execution
- **Start the Main Server:**
  - Run `main_server.py`.
  - When prompted, select the role as `server`.
- **Replica Servers:**
  - Immediately after starting the main server, run `replica_servers.py`.
- **Client Operations:**
  - Run `main_client.py`.
  - Use the command prompt to select and perform the desired operations.
