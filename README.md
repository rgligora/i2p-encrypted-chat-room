# I2P Encrypted Chat Room App

## Overview
This project is an eepsite-based chat room application utilizing Flask and Flask-SocketIO for secure and anonymous communication. It features end-to-end encryption using AES-GCM and RSA algorithms, facilitating secure chat rooms where users can exchange messages in real-time.

## Features
- Anonymous and secure chat rooms on the I2P network.
- End-to-end encryption with RSA and AES-GCM for message security.
- Real-time messaging through WebSockets.
- Configured to run as an eepsite with Nginx reverse proxy.

## Technology Stack
- **Backend:** Flask, Flask-SocketIO
- **Frontend:** HTML, CSS, JavaScript
- **Encryption:** Cryptography library in Python, Web Crypto API
- **Server:** Nginx (reverse proxy configuration for eepsite)


## Setup

### Prerequisites
- I2P Router installed and configured
- Python 3.x
- Nginx

### Installation

### Steps
1. **Clone the repository @ /var/www/ :**

   ```bash
   cd /var/www/
   git clone https://github.com/rgligora/i2p-encrypted-chat-room.git

2. **Navigate to the project directory:**
    ```bash
   cd i2p-encrypted-chat-app

3. **Venv**
   ```bash
   source /venv/bin/activate

4. **Create a symbolic link to this configuration file in the sites-enabled directory:**
   New terminal tab
   ```bash
   cd /var/www/i2p-encrypted-chat-app
   sudo ln -s /var/www/i2p-encrypted-chat-app/chat-app.conf /etc/nginx/sites-enabled

5. **Restart Nginx to apply the changes:**
   ```bash
   sudo service nginx restart

6. **Start the Flask app:**
   ```bash
    gunicorn -k eventlet -w 1 -b 127.0.0.1:443 main:app

7. **Setup the proxy to port 4444**
    In Firefox. Settings > Network Settings > Maunal Proxy Configuration > HTTP Proxy: 127.0.0.1 Port: 4444

8. **Open the eepsite**
    http://nw7ruavzbpwqybf4fdidoyceetwk7rc357q3jevkfvfn7j6hknfa.b32.i2p/
