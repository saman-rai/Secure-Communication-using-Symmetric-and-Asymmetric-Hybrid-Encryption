import tkinter as tk
import socket,threading, gen_key, rsa,os
from tkinter import scrolledtext, filedialog, messagebox
class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Server")
        self.root.geometry("720x480")

       
        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(self.root, height=20, width=80)
        self.chat_display.pack(pady=10)

        # Message entry and send button
        self.message_entry = tk.Entry(self.root, width=60)
        self.message_entry.pack(side=tk.LEFT, padx=10)
        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT)

       

        

        # server init
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 9999))
        self.server_socket.listen(5)

        # Bind window closing event to handle_socket_closure function
        self.root.protocol("WM_DELETE_WINDOW", self.handle_socket_closure)
        # Start server in a new thread
        threading.Thread(target=self.start_server).start()
    def start_server(self):
        try:
            while True:
                self.client_socket, self.client_address = self.server_socket.accept()
                threading.Thread(target=self.handle_client).start()
        except Exception as e:
            print(f"Server error: {e}")
    def handle_client(self):
        try:
            while True:
                message =self.client_socket.recv(1024).decode()
                if not message:
                    break
                elif message == "FILE":
                    self.receive_file()
                if message[:30]=="-----BEGIN RSA PUBLIC KEY-----":
                    print("\n\nClient's Public Key Received\n")
                    print(message,"\n\n")
                    public_key = message
                    self.key,self.salt,self.cipher = gen_key.key()
                    
                    public_key = rsa.PublicKey.load_pkcs1(public_key)
                    
                    message = self.key+b'<,>'+self.salt
                    print("\n\nKey & salt\n")
                    print(self.key, self.salt,"\n\n")

                    encrypted_msg = rsa.encrypt (message, public_key)
                    self.client_socket.sendall(b'<key>'+encrypted_msg)

                    print("\n\nEncrypted Key & Salt\n")
                    print(encrypted_msg,"\n\n")
                else:
                    # self.chat_display.insert(tk.END, f"Client ({self.client_address[0]}:{self.client_address[1]}): {message}\n")
                    self.chat_display.insert(tk.END, f"Client : {message}\n")
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            self.client_socket.close()

    def handle_socket_closure(self):
        try:
            self.server_socket.close()
            self.root.destroy()  # Close the tkinter window
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

  

    def receive_file(self):
        try:
            # Receive file name
            file_name = self.client_socket.recv(1024).decode()
            print(file_name+"!")
            file_name, file_data = file_name.split('<DATA>')
            print(file_data+"!")
            # file_data = self.client_socket.recv(1024)
            
           

            
            file = open(file_name, 'w')
            file.write(file_data)
            file.close()

            self.chat_display.insert(tk.END, f"File received and saved: {file_name}\n")
        except Exception as e:
            messagebox.showerror("File Receive Error", f"Failed to receive or save file: {e}")
   

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()
