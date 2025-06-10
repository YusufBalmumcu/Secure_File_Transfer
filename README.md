# Secure File Transfer 

This project aims to develop a secure file transfer system using encryption methods to ensure confidentiality and integrity during file transmission. It features both a client and a server application, designed for secure data exchange.

## Features

* **Encrypted File Transfer**: Encrypted file transfer has been successfully implemented between the client and server.
* **Protocol Selection**: Users can select between TCP or UDP protocols for file transfer from the client's interface.
* **Hybrid Encryption**: File content is encrypted using the AES algorithm before transfer. The AES key is securely transmitted to the server by encrypting it with the RSA algorithm.
* **Performance Measurement**: The server can measure latency (delay) and bandwidth during data transfer.
* **Graphical User Interface (GUI)**: The application features a Graphical User Interface (GUI).
* **Bonus Features**: Includes hybrid TCP/UDP switching and utilizes encryption libraries (pycryptodome).

## Project Structure

The project consists of two main parts: the client-side and the server-side. Each side has its own encryption module.

* `client.py`: Connects to the server, encrypts the file with AES, encrypts the AES key with RSA, and sends the data.
* `server.py`: Receives data from the client, decrypts the AES key with RSA, decrypts the file content with AES, and saves it.
* `encryption.py`: Contains functions for AES key generation, file encryption/decryption, and RSA encryption/decryption of the AES key.
* `public_key.pem`: RSA public key used by the client for encryption.
* `private_key.pem`: RSA private key used by the server for decryption.

## Technologies Used

| Kütüphane     | Kullanım Amacı                                          |
| :------------ | :------------------------------------------------------ |
| `socket`      | TCP bağlantısı kurmak için                              |
| `pycryptodome`| AES ve RSA şifreleme/çözme işlemleri için               |
| `os`          | Dosya ve klasör işlemleri için                          |
| `tkinter`     | Grafiksel Kullanıcı Arayüzü (GUI) oluşturmak için       |
| `tkinterdnd2` | GUI'ye sürükle ve bırak (drag-and-drop) özelliği eklemek için |

## How to Run

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/YusufBalmumcu/Secure_File_Transfer
    cd Secure_File_Transfer
    ```
2.  **Install dependencies:**
    ```bash
    pip install pycryptodome tkinterdnd2
    ```
3.  **Ensure Keys are Present**: Make sure `public_key.pem` and `private_key.pem` are in your project directory. (You might need to generate these if they are not provided, using `Crypto.PublicKey.RSA.generate(2048)` and saving them.)
4.  **Run the Server:**
    ```bash
    python server.py
    ```
    The server GUI will open. Click "Sunucuyu Başlat" (Start Server). The server waits for a connection at the specified address (127.0.0.1:65432).
5.  **Run the Client:**
    ```bash
    python client.py
    ```
    The client GUI will open. You can select a file using the "Dosya Seç" (Select File) button or by dragging and dropping it. Then, select the protocol, enter the IP and PORT (e.g., `127.0.0.1` and `65432`), and click "Dosyayı Gönder" (Send File).

## Future Improvements

* File integrity control (e.g., SHA-256 hash control).
* Client-side interface and authentication processes.
* Fragmentation & Reassembly (planned but not implemented).
* Attack Simulations (planned but not implemented).
* Packet Loss Handling/Performance Comparison (planned but not implemented).
