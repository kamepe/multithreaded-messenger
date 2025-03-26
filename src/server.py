import socket
import threading
import sqlite3
import json
import os
import time
from cryptography.fernet import Fernet
import queue

# Global variables
HOST = '127.0.0.1'
PORT = 5555
MAX_CLIENTS = 3  # Maximum number of concurrent clients
client_semaphore = threading.Semaphore(MAX_CLIENTS)
waiting_queue = queue.Queue()
active_clients = {}  # Dictionary to store active clients {username: socket}
lock = threading.Lock()  # Lock for thread synchronization
FILE_CHUNK_SIZE = 1024  # Size of chunks for file transfer
time
# Permanent encryption key - DO NOT CHANGE or users won't be able to login
# This is a valid Fernet key (32 url-safe base64-encoded bytes)
ENCRYPTION_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
cipher_suite = Fernet(ENCRYPTION_KEY)

# Initialize database
def init_db():
    conn = sqlite3.connect('lu_connect.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized")

# Handle client authentication
def authenticate_client(client_socket):
    while True:
        try:
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                return None
            
            request = json.loads(data)
            request_type = request.get('type')
            username = request.get('username')
            password = request.get('password')
            
            if request_type == 'register':
                success = register_user(username, password, client_socket)
                if success:
                    return username
            elif request_type == 'login':
                success = login_user(username, password, client_socket)
                if success:
                    return username
            else:
                response = {'status': 'error', 'message': 'Invalid request type'}
                client_socket.send(json.dumps(response).encode('utf-8'))
        
        except Exception as e:
            print(f"Authentication error: {e}")
            return None

# Register a new user
def register_user(username, password, client_socket):
    conn = sqlite3.connect('lu_connect.db')
    cursor = conn.cursor()
    
    try:
        # check if username already exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            response = {'status': 'error', 'message': 'Username already exists'}
            client_socket.send(json.dumps(response).encode('utf-8'))
            return False
        
        # Encrypt password
        encrypted_password = cipher_suite.encrypt(password.encode('utf-8')).decode('utf-8')
        
        # Insert new user
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, encrypted_password))
        conn.commit()
        
        response = {'status': 'success', 'message': 'Registration successful'}
        client_socket.send(json.dumps(response).encode('utf-8'))
        return False
    
    except Exception as e:
        conn.rollback()
        response = {'status': 'error', 'message': f'Registration failed: {str(e)}'}
        client_socket.send(json.dumps(response).encode('utf-8'))
        return False
    
    finally:
        conn.close()

# Login a user
def login_user(username, password, client_socket):
    conn = sqlite3.connect('lu_connect.db')
    cursor = conn.cursor()
    
    try:
        # Check if username exists
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if not result:
            response = {'status': 'error', 'message': 'Invalid username or password'}
            client_socket.send(json.dumps(response).encode('utf-8'))
            return False
        
        # Verify password
        stored_password = result[0]
        try:
            decrypted_password = cipher_suite.decrypt(stored_password.encode('utf-8')).decode('utf-8')
            if password != decrypted_password:
                response = {'status': 'error', 'message': 'Invalid username or password'}
                client_socket.send(json.dumps(response).encode('utf-8'))
                return False
        except Exception as e:
            print(f"Password decryption error: {e}")
            response = {'status': 'error', 'message': 'Invalid username or password'}
            client_socket.send(json.dumps(response).encode('utf-8'))
            return False
        
        response = {'status': 'success', 'message': 'Login successful'}
        client_socket.send(json.dumps(response).encode('utf-8'))
        return True
    
    except Exception as e:
        response = {'status': 'error', 'message': f'Login failed: {str(e)}'}
        client_socket.send(json.dumps(response).encode('utf-8'))
        return False
    
    finally:
        conn.close()

# Handle client connection
def handle_client(client_socket, addr):
    try:
        # set socket timeout
        client_socket.settimeout(30)
        
        # Authenticate client
        username = authenticate_client(client_socket)
        if not username:
            print(f"Authentication failed for {addr}")
            client_socket.close()
            client_semaphore.release()
            check_waiting_queue()
            return
        
        # Add client to active clients
        with lock:
            active_clients[username] = client_socket
        
        print(f"User {username} connected from {addr}")
        
        # Handle client messages
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                message = json.loads(data.decode('utf-8'))
                message_type = message.get('type')
                
                if message_type == 'text':
                    handle_text_message(message, username)
                elif message_type == 'file_info':
                    handle_file_info(message, username, client_socket)
            except socket.timeout:
                continue
            except Exception as e:
                break
        
        # Cleanup when client disconnects
        with lock:
            if username in active_clients:
                del active_clients[username]
        
        print(f"{username} disconnected")
        client_socket.close()
        client_semaphore.release()
        
        # Check the waiting queue to accept next client
        check_waiting_queue()
    
    except Exception as e:
        print(f"Error handling client: {e}")
        client_socket.close()
        client_semaphore.release()
        check_waiting_queue()

# Handle text message
def handle_text_message(message, sender):
    recipient = message.get('recipient')
    text = message.get('text')
    timestamp = message.get('timestamp')
    
    # Store message in database
    conn = sqlite3.connect('lu_connect.db')
    cursor = conn.cursor()

    # Encrypt message
    encrypted_text = cipher_suite.encrypt(text.encode('utf-8')).decode('utf-8')
    
    cursor.execute(
        "INSERT INTO messages (sender, recipient, message, timestamp) VALUES (?, ?, ?, ?)",
        (sender, recipient, encrypted_text, timestamp)
    )
    conn.commit()

    conn.close()
    
    # Forward message to recipient if online
    with lock:
        if recipient in active_clients:
            recipient_socket = active_clients[recipient]
            try:
                forward_message = {
                    'type': 'text',
                    'sender': sender,
                    'text': text,
                    'timestamp': timestamp
                }
                recipient_socket.send(json.dumps(forward_message).encode('utf-8'))
            except Exception as e:
                print(f"Error forwarding message: {e}")

# Handle file information
def handle_file_info(message, sender, client_socket):
    recipient = message.get('recipient')
    filename = message.get('filename')
    filesize = message.get('filesize')
    filetype = os.path.splitext(filename)[1].lower()
    timestamp = message.get('timestamp')
    
    # Check if allowed
    allowed_types = ['.docx', '.pdf', '.jpeg']
    if filetype not in allowed_types:
        response = {
            'type': 'file_rejected',
            'message': 'File type not allowed. Only .docx, .pdf, and .jpeg files are allowed.'
        }
        client_socket.send(json.dumps(response).encode('utf-8'))
        return
    
    # Prepare to receive file
    response = {
        'type': 'ready_for_file',
        'message': 'Ready to receive file'
    }
    client_socket.send(json.dumps(response).encode('utf-8'))
    
    # Receive file data
    try:
        # Set a larger timeout for file transfer
        client_socket.settimeout(60)
        
        file_data = b''
        remaining = filesize
        
        while remaining > 0:
            chunk_size = min(FILE_CHUNK_SIZE, remaining)
            chunk = client_socket.recv(chunk_size)
            if not chunk:
                print(f"Connection closed during file transfer from {sender}")
                break
            file_data += chunk
            remaining -= len(chunk)
        
        # Reset timeout after file transfer
        client_socket.settimeout(30)
        
        # Encrypt file data
        encrypted_data = cipher_suite.encrypt(file_data)
        
        # Save file
        file_dir = 'files'
        if not os.path.exists(file_dir):
            os.makedirs(file_dir)
        
        encrypted_filename = f"{file_dir}/{sender}_{recipient}_{timestamp.replace(':', '-').replace(' ', '_')}{filetype}"
        
        with open(encrypted_filename, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"File '{filename}' from {sender} to {recipient} saved as {encrypted_filename}")
        
        # Forward file to recipient
        with lock:
            if recipient in active_clients:
                recipient_socket = active_clients[recipient]
                try:
                    # Send file info
                    file_info = {
                        'type': 'file_info',
                        'sender': sender,
                        'filename': filename,
                        'filesize': filesize,
                        'timestamp': timestamp
                    }
                    recipient_socket.send(json.dumps(file_info).encode('utf-8'))
                    
                    # Wait for recipient to be ready
                    recipient_socket.settimeout(30)  # Set timeout for recipient response
                    recipient_response_data = recipient_socket.recv(1024)
                    recipient_response = json.loads(recipient_response_data.decode('utf-8'))
                    
                    if recipient_response.get('type') == 'ready_for_file':
                        # Send file data in chunks
                        bytes_sent = 0
                        while bytes_sent < len(file_data):
                            chunk_size = min(FILE_CHUNK_SIZE, len(file_data) - bytes_sent)
                            # Extract chunk
                            chunk = file_data[bytes_sent:bytes_sent + chunk_size]
                            # Send chunk
                            recipient_socket.sendall(chunk)
                            # Update bytes sent
                            bytes_sent += chunk_size
                        
                        print(f"File transferred from {sender} to {recipient} successfully")
                except Exception as e:
                    print(f"Error forwarding file to {recipient}: {e}")
    
    except socket.timeout:
        print(f"Timeout during file transfer from {sender}")
    except Exception as e:
        print(f"Error in file transfer: {e}")
    finally:
        # Reset timeout
        client_socket.settimeout(30)

# Check waiting queue
def check_waiting_queue():
    if not waiting_queue.empty():
        client_socket, addr, wait_start = waiting_queue.get()
        
        # Send notification to client that they're being connected
        try:
            notification = {
                'type': 'queue_update',
                'status': 'connecting',
                'message': 'A slot has opened up. Connecting you now...'
            }
            client_socket.send(json.dumps(notification).encode('utf-8'))
            
            time.sleep(0.5)  # Give client time to process the message
        except Exception as e:
            print(f"Error notifying client {addr}: {e}")
        
        # The semaphore should be available
        client_semaphore.acquire(blocking=True)
        
        # Accept the client
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()
        
        # Update remaining clients in the queue
        update_waiting_clients()

# Update all clients in the waiting queue
def update_waiting_clients():
    if waiting_queue.empty():
        return
        
    # Make a copy of the queue to iterate through
    temp_queue = queue.Queue()
    position = 1
    
    # Process each client in the queue
    while not waiting_queue.empty():
        client_socket, addr, wait_start = waiting_queue.get()
        
        # Send update to client
        try:
            update = {
                'type': 'queue_update',
                'status': 'waiting',
                'position': position,
                'message': f"Your position is now {position}."
            }
            client_socket.send(json.dumps(update).encode('utf-8'))
        except:
            continue
            
        # Add back to temporary queue
        temp_queue.put((client_socket, addr, wait_start))
        position += 1
    
    # Restore the queue
    while not temp_queue.empty():
        waiting_queue.put(temp_queue.get())

# Periodic queue update
def start_queue_update_timer():
    # Update queue every 30 seconds
    threading.Timer(30.0, send_queue_updates).start()

def send_queue_updates():
    # Update waiting clients
    if not waiting_queue.empty():
        update_waiting_clients()
    
    start_queue_update_timer()

# Main server function
def start_server():
    init_db()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    
    print(f"Server started on {HOST}:{PORT}")
    
    # Start periodic queue updates
    start_queue_update_timer()
    
    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")
            
            # Try to acquire the semaphore
            if client_semaphore.acquire(blocking=False):
                # handle the client
                threading.Thread(target=handle_client, args=(client_socket, addr)).start()
            else:
                # Add to waiting queue
                wait_start = time.time()
                waiting_queue.put((client_socket, addr, wait_start))
                
                # Inform client about waiting
                wait_position = waiting_queue.qsize()
                
                response = {
                    'type': 'waiting',
                    'status': 'waiting',
                    'position': wait_position,
                    'message': f"Server is full. You are in position {wait_position} in the queue."
                }
                client_socket.send(json.dumps(response).encode('utf-8'))
    
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()