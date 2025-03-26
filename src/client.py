import socket
import threading
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from datetime import datetime

# Global variables
HOST = '127.0.0.1'
PORT = 5555
client_socket = None
current_username = None

# Create a socket and connect to the server
def connect_to_server():
    global client_socket
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        return True
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect to server: {str(e)}")
        return False

# Register a new user
def register(username, password):
    global client_socket
    
    if not connect_to_server():
        return
    
    # Send registration request
    request = {
        'type': 'register',
        'username': username,
        'password': password
    }
    client_socket.send(json.dumps(request).encode('utf-8'))
    
    # Receive response
    response = json.loads(client_socket.recv(1024).decode('utf-8'))
    
    if response.get('type') == 'waiting':
        position = response.get('position', 0)
        show_waiting_frame(position, response.get('message', ''))
        # Start a thread to receive messages (for queue updates)
        threading.Thread(target=receive_messages, daemon=True).start()
        return
    
    # Normal response handling
    if response.get('status') == 'success':
        messagebox.showinfo("Registration", "Registration successful! You can now log in.")
        show_login_frame()
    else:
        messagebox.showerror("Registration Error", response.get('message', 'Unknown error'))
    
    # Close the connection after registration
    client_socket.close()
    client_socket = None

# Login a user
def login(username, password):
    global current_username, client_socket
    
    if not connect_to_server():
        return
    
    # Send login request
    request = {
        'type': 'login',
        'username': username,
        'password': password
    }
    client_socket.send(json.dumps(request).encode('utf-8'))
    
    # Receive response
    response = json.loads(client_socket.recv(1024).decode('utf-8'))
    
    # Check if put in a waiting queue
    if response.get('type') == 'waiting':
        current_username = username  # Save for when get connected
        position = response.get('position', 0)
        show_waiting_frame(position, response.get('message', ''))
        # Start a thread to receive messages
        threading.Thread(target=receive_messages, daemon=True).start()
        return
    
    # Normal login response handling
    if response.get('status') == 'success':
        current_username = username
        user_label.config(text=f"Logged in as: {current_username}")
        show_chat_frame()
        
        # Start a thread to receive messages
        threading.Thread(target=receive_messages, daemon=True).start()
    else:
        messagebox.showerror("Login Error", response.get('message', 'Unknown error'))
        client_socket.close()
        client_socket = None

# Send a text message
def send_message():
    recipient = recipient_input.get()
    text = message_input.get()
    
    if not recipient or not text:
        messagebox.showerror("Error", "Recipient and message are required")
        return
    
    if not client_socket:
        messagebox.showerror("Connection Error", "Not connected to server")
        return
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = {
        'type': 'text',
        'recipient': recipient,
        'text': text,
        'timestamp': timestamp
    }
    client_socket.send(json.dumps(message).encode('utf-8'))
    
    # Update chat display
    chat_display.config(state=tk.NORMAL)
    chat_display.insert(tk.END, f"[{timestamp}] You to {recipient}: {text}\n")
    chat_display.config(state=tk.DISABLED)
    chat_display.see(tk.END)
    
    # Clear message input
    message_input.delete(0, tk.END)

# Choose a file to send
def choose_file():
    recipient = recipient_input.get()
    if not recipient:
        messagebox.showerror("Error", "Please enter a recipient username")
        return
    
    file_types = [
        ('Word Documents', '*.docx'),
        ('PDF Files', '*.pdf'),
        ('JPEG Images', '*.jpeg')
    ]
    
    filepath = filedialog.askopenfilename(
        title="Select a file",
        filetypes=file_types
    )
    
    if filepath:
        send_file(recipient, filepath)

# Send a file
def send_file(recipient, filepath):
    if not client_socket:
        messagebox.showerror("Connection Error", "Not connected to server")
        return
    
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Send file info
    file_info = {
        'type': 'file_info',
        'recipient': recipient,
        'filename': filename,
        'filesize': filesize,
        'timestamp': timestamp
    }
    client_socket.send(json.dumps(file_info).encode('utf-8'))
    
    # Wait for server to be ready
    response = json.loads(client_socket.recv(4096).decode('utf-8'))
    
    if response.get('type') == 'ready_for_file':
        # Send file data
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                client_socket.sendall(chunk)
        
        # Update chat display
        chat_display.config(state=tk.NORMAL)
        chat_display.insert(tk.END, f"[{timestamp}] You sent file '{filename}' to {recipient}\n")
        chat_display.config(state=tk.DISABLED)
        chat_display.see(tk.END)
    
    elif response.get('type') == 'file_rejected':
        messagebox.showerror("File Rejected", response.get('message', 'File was rejected'))

# Receive messages from the server
def receive_messages():
    global client_socket
    
    while True:
        try:
            if not client_socket:
                break
            
            data = client_socket.recv(4096)
            if not data:
                break
            
            # Try to decode as JSON
            try:
                message = json.loads(data.decode('utf-8'))
                message_type = message.get('type')
                
                if message_type == 'text':
                    handle_text_message(message)
                elif message_type == 'file_info':
                    handle_file_info(message)
                elif message_type == 'waiting':
                    handle_waiting_message(message)
                elif message_type == 'queue_update':
                    # Server sent an update about queue position
                    handle_waiting_message(message)
            
            # If not JSON, it might be file data
            except json.JSONDecodeError:
                pass
        
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    
    # connection is closed
    messagebox.showinfo("Disconnected", "You have been disconnected from the server")
    client_socket = None
    show_login_frame()

# Handle incoming text message
def handle_text_message(message):
    sender = message.get('sender')
    text = message.get('text')
    timestamp = message.get('timestamp')
    
    # Update chat display
    chat_display.config(state=tk.NORMAL)
    chat_display.insert(tk.END, f"[{timestamp}] {sender}: {text}\n")
    chat_display.config(state=tk.DISABLED)
    chat_display.see(tk.END)

# Handle incoming file info
def handle_file_info(message):
    sender = message.get('sender')
    filename = message.get('filename')
    filesize = message.get('filesize')
    timestamp = message.get('timestamp')
    
    # Ask user if they want to accept the file
    accept = messagebox.askyesno(
        "File Received",
        f"{sender} wants to send you a file: {filename} ({filesize} bytes)\nDo you want to accept it?"
    )
    
    if accept:
        # Send ready message
        ready_message = {
            'type': 'ready_for_file',
            'message': 'Ready to receive file'
        }
        client_socket.send(json.dumps(ready_message).encode('utf-8'))
        
        # Receive file data
        file_data = b''
        remaining = filesize
        
        while remaining > 0:
            chunk = client_socket.recv(min(4096, remaining))
            if not chunk:
                break
            file_data += chunk
            remaining -= len(chunk)
        
        # Ask user where to save the file
        file_types = [
            ('Word Documents', '*.docx'),
            ('PDF Files', '*.pdf'),
            ('JPEG Images', '*.jpeg')
        ]
        
        save_path = filedialog.asksaveasfilename(
            title="Save File",
            initialfile=filename,
            filetypes=file_types
        )
        
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(file_data)
            
            # Update chat display
            chat_display.config(state=tk.NORMAL)
            chat_display.insert(tk.END, f"[{timestamp}] Received file '{filename}' from {sender}\n")
            chat_display.config(state=tk.DISABLED)
            chat_display.see(tk.END)
    else:
        # Send reject message
        reject_message = {
            'type': 'file_rejected',
            'message': 'User rejected the file'
        }
        client_socket.send(json.dumps(reject_message).encode('utf-8'))

# Handle waiting message
def handle_waiting_message(message):
    position = message.get('position', 0)
    status_msg = message.get('message', '')
    queue_status = message.get('status', 'waiting')
    
    # Check if being connected
    if queue_status == 'connecting':
        status_label.config(text=f"Status: {status_msg}")
        
        user_label.config(text=f"Logged in as: {current_username}")
        show_chat_frame()
        return
        
    # Normal waiting status update
    show_waiting_frame(position, status_msg)

# Show the waiting frame
def show_waiting_frame(position, status_msg=None):
    hide_all_frames()
    waiting_frame.pack(fill=tk.BOTH, expand=True)
    
    # Update waiting labels
    position_label.config(text=f"Your position in queue: {position}")
    
    if status_msg:
        status_label.config(text=f"Status: {status_msg}")

# Disconnect from the server
def disconnect():
    global client_socket
    
    if client_socket:
        try:
            client_socket.close()
        except:
            pass
        client_socket = None
    
    show_login_frame()

# GUI Setup
root = tk.Tk()
root.title("LU-Connect")
root.geometry("800x600")
root.minsize(800, 600)

# Dark Theme Colors
bg_color = "#2E2E2E"
text_color = "#FFFFFF"
accent_color = "#3F3F3F"
button_bg = "#444444"
button_fg = "#FFFFFF"
entry_bg = "#3F3F3F"
entry_fg = "#FFFFFF"

# Configure dark theme
root.configure(bg=bg_color)
style = ttk.Style()
style.theme_use('default')

# Configure ttk styles
style.configure('TFrame', background=bg_color)
style.configure('TLabel', background=bg_color, foreground=text_color)
style.configure('TButton', background=button_bg, foreground=button_fg)
style.configure('TEntry', fieldbackground=entry_bg, foreground=entry_fg)
style.map('TButton', 
    background=[('active', button_bg), ('pressed', button_bg)],
    foreground=[('active', button_fg), ('pressed', button_fg)]
)

# Create frames
login_frame = ttk.Frame(root, padding=20)
register_frame = ttk.Frame(root, padding=20)
chat_frame = ttk.Frame(root, padding=20)
waiting_frame = ttk.Frame(root, padding=20)

# Hide all frames
def hide_all_frames():
    login_frame.pack_forget()
    register_frame.pack_forget()
    chat_frame.pack_forget()
    waiting_frame.pack_forget()

# Show login frame
def show_login_frame():
    hide_all_frames()
    login_frame.pack(fill=tk.BOTH, expand=True)

# Show register frame
def show_register_frame():
    hide_all_frames()
    register_frame.pack(fill=tk.BOTH, expand=True)

# Show chat frame
def show_chat_frame():
    hide_all_frames()
    chat_frame.pack(fill=tk.BOTH, expand=True)

# ---- Login Frame ----
ttk.Label(login_frame, text="LU-Connect", font=("Arial", 24)).pack(pady=20)
ttk.Label(login_frame, text="Login", font=("Arial", 16)).pack(pady=10)

login_username_var = tk.StringVar()
login_password_var = tk.StringVar()

ttk.Label(login_frame, text="Username:").pack(anchor=tk.W, pady=(10, 2))
ttk.Entry(login_frame, textvariable=login_username_var, width=30).pack(fill=tk.X, pady=(0, 10))

ttk.Label(login_frame, text="Password:").pack(anchor=tk.W, pady=(10, 2))
ttk.Entry(login_frame, textvariable=login_password_var, show="*", width=30).pack(fill=tk.X, pady=(0, 10))

login_button = ttk.Button(
    login_frame,
    text="Login",
    command=lambda: login(login_username_var.get(), login_password_var.get())
)
login_button.pack(pady=10)

register_link = ttk.Button(
    login_frame,
    text="Don't have an account? Register",
    command=show_register_frame
)
register_link.pack(pady=10)

# ---- Register Frame ----
ttk.Label(register_frame, text="LU-Connect", font=("Arial", 24)).pack(pady=20)
ttk.Label(register_frame, text="Register", font=("Arial", 16)).pack(pady=10)

register_username_var = tk.StringVar()
register_password_var = tk.StringVar()
register_confirm_var = tk.StringVar()

ttk.Label(register_frame, text="Username:").pack(anchor=tk.W, pady=(10, 2))
ttk.Entry(register_frame, textvariable=register_username_var, width=30).pack(fill=tk.X, pady=(0, 10))

ttk.Label(register_frame, text="Password:").pack(anchor=tk.W, pady=(10, 2))
ttk.Entry(register_frame, textvariable=register_password_var, show="*", width=30).pack(fill=tk.X, pady=(0, 10))

ttk.Label(register_frame, text="Confirm Password:").pack(anchor=tk.W, pady=(10, 2))
ttk.Entry(register_frame, textvariable=register_confirm_var, show="*", width=30).pack(fill=tk.X, pady=(0, 10))

def register_submit():
    username = register_username_var.get()
    password = register_password_var.get()
    confirm = register_confirm_var.get()
    
    if not username or not password:
        messagebox.showerror("Registration Error", "Username and password are required")
        return
    
    if password != confirm:
        messagebox.showerror("Registration Error", "Passwords do not match")
        return
    
    register(username, password)

register_button = ttk.Button(
    register_frame,
    text="Register",
    command=register_submit
)
register_button.pack(pady=10)

login_link = ttk.Button(
    register_frame,
    text="Already have an account? Login",
    command=show_login_frame
)
login_link.pack(pady=10)

# ---- Chat Frame ----
# Top section - User info and logout
top_frame = ttk.Frame(chat_frame)
top_frame.pack(fill=tk.X, pady=10)

user_label = ttk.Label(top_frame, text="", font=("Arial", 12))
user_label.pack(side=tk.LEFT)

logout_button = ttk.Button(
    top_frame,
    text="Logout",
    command=disconnect
)
logout_button.pack(side=tk.RIGHT)

# Middle section - Chat display
chat_display = tk.Text(chat_frame, state=tk.DISABLED, wrap=tk.WORD, bg=accent_color, fg=text_color)
chat_display.pack(fill=tk.BOTH, expand=True, pady=10)

# Bottom section - Message input and send
bottom_frame = ttk.Frame(chat_frame)
bottom_frame.pack(fill=tk.X, pady=10)

ttk.Label(bottom_frame, text="To:").pack(side=tk.LEFT, padx=(0, 5))
recipient_input = ttk.Entry(bottom_frame, width=15)
recipient_input.pack(side=tk.LEFT, padx=(0, 10))

message_input = ttk.Entry(bottom_frame)
message_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

send_button = ttk.Button(
    bottom_frame,
    text="Send",
    command=send_message
)
send_button.pack(side=tk.LEFT, padx=(0, 10))

file_button = ttk.Button(
    bottom_frame,
    text="Send File",
    command=choose_file
)
file_button.pack(side=tk.LEFT)

# Enter key to send message
def on_enter(event):
    send_message()

message_input.bind("<Return>", on_enter)

# ---- Waiting Frame ----
ttk.Label(waiting_frame, text="Waiting in Queue", font=("Arial", 16)).pack(pady=20)

ttk.Label(waiting_frame, text="The server has reached its maximum capacity (3 users).", font=("Arial", 11)).pack(pady=5)
ttk.Label(waiting_frame, text="Please wait for a connection slot to become available.", font=("Arial", 11)).pack(pady=5)

position_label = ttk.Label(waiting_frame, text="Your position in queue: 0", font=("Arial", 14, "bold"))
position_label.pack(pady=20)

status_label = ttk.Label(waiting_frame, text="Status: Waiting for a slot to open...", font=("Arial", 11, "italic"))
status_label.pack(pady=15)

progress = ttk.Progressbar(waiting_frame, orient="horizontal", length=300, mode="indeterminate")
progress.pack(pady=15)
progress.start(10)

cancel_button = ttk.Button(
    waiting_frame,
    text="Cancel",
    command=disconnect
)
cancel_button.pack(pady=20)

# Start with login frame
show_login_frame()

# Main loop
if __name__ == "__main__":
    root.mainloop()
    
    # Clean up
    if client_socket:
        client_socket.close()