import tkinter as tk
import socket
import threading
from tkinter import scrolledtext, filedialog, messagebox
import rsa_key
import rsa
from Crypto.Cipher import AES
class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Client")
        self.root.geometry("720x480")

        # Client socket initialization
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       
        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(self.root, height=20, width=80)
        self.chat_display.pack(pady=10)

        # Message entry and send button
        self.message_entry = tk.Entry(self.root, width=60)
        self.message_entry.pack(side=tk.LEFT, padx=10)
        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT)

        # Connect to server button
        self.connect_button = tk.Button(self.root, text="Connect to Server", command=self.connect_to_server)
        self.connect_button.pack(pady=10)

        # File receive button
        self.file_button = tk.Button(self.root, text="Send File", command=self.send_file)
        self.file_button.pack(pady=10)


        # Bind window closing event to handle_socket_closure function
        self.root.protocol("WM_DELETE_WINDOW", self.handle_socket_closure)

    def connect_to_server(self):
        try:
            self.client_socket.connect(('localhost', 9999))
            self.chat_display.insert(tk.END, "Connected to server\n")
        
            threading.Thread(target=self.receive_messages).start()

            self.public_key, self.private_key = rsa_key.gen_Asym_key()

           # Serialize the public key to PEM format
            public_key_pem = self.public_key.save_pkcs1().decode()
            private_key_pem = self.private_key.save_pkcs1().decode()

            self.client_socket.sendall(public_key_pem.encode())


            print("\n\nPublic Key :\n")
            print(public_key_pem.encode(), "\n\n")

            print("Private Key :\n")
            print(private_key_pem.encode(),"\n\n")

        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
    def handle_socket_closure(self):
        try:
            # self.client_socket.shutdown(socket.SHUT_RDWR)
            self.client_socket.close()
            self.root.destroy()
        except Exception as e:
            pass  # Handle any socket closing errors gracefully
    def send_message(self):
        message = self.message_entry.get()
        if message:
            try:
                ciphertext = self.cipher.encrypt (message.encode())

                print("\n\nCiphered message\n")
                print(ciphertext,"\n\n")
                self.client_socket.sendall(message.encode())

                self.chat_display.insert(tk.END, f"You: {message}\n")
                self.message_entry.delete(0, tk.END)  # Clear the message entry
            except Exception as e:
                messagebox.showerror("Send Error", f"Failed to send message: {e}")

    def receive_messages(self):
        try:
            while True:
                message = self.client_socket.recv(1024)
                if message[:5].decode()=="<key>":
                    print("\n\nEncrypted Key & Salt received from Server\n")
                    print(message,"\n\n")
                    encrypted_key = message[5:]

                    clear_message = rsa.decrypt (encrypted_key, self.private_key)
                    self.key, self.salt = clear_message.split(b"<,>")
                    self.cipher = AES.new(self.key, AES.MODE_EAX, self.salt)
                
                elif not message.decode():
                    break
                else:
                    message = message.decode()
                    self.chat_display.insert(tk.END, f"Server: {message}\n")
        except Exception as e:
            print(f"Receive error: {e}")
    def send_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Send")
        if file_path:
            try:
                file_name = file_path.split('/')[-1]  # Extract file name from path
                self.chat_display.insert(tk.END, f"Sending file: {file_name}\n")
                with open(file_path, 'r') as file:
                    file_data = file.read()
                self.client_socket.sendall(b"FILE")  # Send file indicator

                self.client_socket.sendall(file_name.encode())  # Send file name
                self.client_socket.sendall(('<DATA>'+file_data).encode())  # Send file data
                self.chat_display.insert(tk.END, "File sent successfully\n")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send file: {e}")

   

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
