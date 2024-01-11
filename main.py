from flask import Flask, render_template, request, session, redirect, url_for, request
from flask_socketio import join_room, leave_room, send, emit, SocketIO
import random
import base64
import os
from string import ascii_uppercase
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


app = Flask(__name__)
app.config["SECRET_KEY"] = "i2pchatroom"
socketio = SocketIO(app, cors_allowed_origins='*')
rooms = {}

def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        
        if code not in rooms:
            break
    
    return code

def decrypt_with_private_key(encrypted_data, private_key):
    try:
        # Load the private key
        private_key_obj = serialization.load_der_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )

        # Decrypt the data
        decrypted_data = private_key_obj.decrypt(
            base64.b64decode(encrypted_data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def encrypt_message(key, message):
    try:
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes long for AES-256.")
        
        # Ensure the message is in bytes
        if isinstance(message, str):
            message = message.encode()

        # Generate a random IV for AES-GCM
        iv = os.urandom(12)

        # Initialize AESGCM cipher with the given key
        aesgcm = AESGCM(key)

        # Encrypt the message
        ct = aesgcm.encrypt(iv, message, None)

        # Return IV + ciphertext for transmission
        return iv + ct
    except Exception as e:
        print(f"Message encription failed: {e}")
        return None

  


def decrypt_message(key, encrypted_message_base64):
    try:
        encrypted_message = base64.b64decode(encrypted_message_base64)
        # The first 12 bytes are the IV
        iv = encrypted_message[:12]
        # The rest is the actual ciphertext
        ct = encrypted_message[12:]

        # Initialize AESGCM with the given key
        aesgcm = AESGCM(key)

        # Decrypt the message
        return aesgcm.decrypt(iv, ct, None)
    except Exception as e:
        print(f"Message decryption failed: {e}")
        return None


@app.route("/", methods=["POST", "GET"])
def home():
    session.clear()
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not name:
            return render_template("home.html", error="Please enter a name.", code=code, name=name)

        if join != False and not code:
            return render_template("home.html", error="Please enter a room code.", code=code, name=name)
        
        room = code
        if create != False:
            room = generate_unique_code(4)

            # Generate an RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=1024,
            )
            public_key = private_key.public_key()

            # Serialize public key to use in your application
            der_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Optionally, serialize the private key if needed
            der_private_key = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )


            rooms[room] = {"members": {}, "messages": [], "public_key": der_public_key, "private_key": der_private_key}
        elif code not in rooms:
            return render_template("home.html", error="Room does not exist.", code=code, name=name)
        
        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))
    
    return render_template("home.html")

@app.route("/room")
def room():
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("home"))

    der_public_key = rooms[room]["public_key"]
    public_key_b64 = base64.b64encode(der_public_key).decode('utf-8')


    return render_template("room.html", code=room, public_key=public_key_b64)



@socketio.on("message")
def message(data):
    room = session.get("room")
    name = session.get("name")
    if room not in rooms:
        return 

    senders_sym_key = rooms[room]['members'][name]['symmetric_key']
    encrypted_message = data["data"]
    decrypted_message = decrypt_message(senders_sym_key, encrypted_message).decode('utf-8')
    rooms[room]["messages"].append(decrypted_message)


    for member in rooms[room]['members'].keys():
        temp_key = rooms[room]['members'][member]['symmetric_key']
        encrypted_message_for_member = encrypt_message(temp_key, decrypted_message)
        
        content = {
            "name": session.get("name"),
            "message": base64.b64encode(encrypted_message_for_member).decode('utf-8'),
            "is_self": session.get("name")
        }
        
        
        # send the encrypted message to each member
        send(content, to=rooms[room]['members'][member]['sid'])


@socketio.on("connect")
def connect(auth):
    encrypted_symmetric_key = auth.get("symmetric_key")
    room = session.get("room")
    name = session.get("name")
    sid = request.sid
    print(f"User {name} connected with key: {encrypted_symmetric_key}")
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    decrypted_symmetric_key = decrypt_with_private_key(encrypted_symmetric_key, rooms[room]["private_key"])
    if decrypted_symmetric_key is not None:
        decrypted_key_base64 = base64.b64encode(decrypted_symmetric_key).decode('utf-8')
    else:
        print("Decryption failed.")

    rooms[room]['members'][name] = {'symmetric_key': decrypted_symmetric_key, 'sid': sid}

    rooms[room]["messages"].append({"name": name, "message": 'has entered the room', "is_self": name})

    for member in rooms[room]['members'].keys():
        temp_key = rooms[room]['members'][member]['symmetric_key']
        encrypted_message_for_member = encrypt_message(temp_key, "has entered the room")
        
        content = {
            "name": session.get("name"),
            "message": base64.b64encode(encrypted_message_for_member).decode('utf-8'),
            "is_self": session.get("name")
        }
        
        # send the encrypted message to each member
        send(content, to=rooms[room]['members'][member]['sid'])

    
    emit('update_user_list', list(rooms[room]['members'].keys()), room=room) 

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    
    if room in rooms:
        rooms[room]['members'].pop(name)
        emit('update_user_list', list(rooms[room]['members'].keys()), room=room)
        if len(rooms[room]["members"]) <= 0:
            del rooms[room]
            print(f"Deleting the room {room}, because it is empty")
        else:
            for member in rooms[room]['members'].keys():
                temp_key = rooms[room]['members'][member]['symmetric_key']
                encrypted_message_for_member = encrypt_message(temp_key, "has left the room")
                
                content = {
                    "name": session.get("name"),
                    "message": base64.b64encode(encrypted_message_for_member).decode('utf-8'),
                    "is_self": session.get("name")
                }
                
                # send the encrypted message to each member
                send(content, to=rooms[room]['members'][member]['sid'])
            print(f"{name} has left the room {room}")

    
    

@socketio.on_error_default
def error_handler(e):
    print(f"WebSocket Error: {str(e)}")

if __name__ == "__main__":
    socketio.run(app, debug=True)