import socket
import json
import threading
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from xml.etree import ElementTree
from GUI import GUI


class ClientApp(GUI):
    def __init__(self, root):
        super().__init__(root)
        self.sock = None
        self.username = None
        self.connect_to_server()
        self.contacts = self.read_contacts_from_xml()
        for contact in self.contacts:
            self.contact_list.insert(tk.END, contact)
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def read_xml(self, keyword):
        try:
            tree = ElementTree.parse(r'data/client.xml')
            root = tree.getroot()
            return root.find(f".//{keyword}").text
        except AttributeError as e:
            raise ValueError(f"Keyword '{keyword}' not found in XML or invalid format.") from e

    @staticmethod
    def read_contacts_from_xml():
        import xml.etree.ElementTree as ElementTree
        try:
            tree = ElementTree.parse(r'data/client.xml')
            root = tree.getroot()
            contacts = [contact.text for contact in root.findall(".//contact/username")]
            return contacts
        except Exception as e:
            print(f"Error reading contacts from XML: {e}")
            return []

    def connect_to_server(self):
        try:
            server_ip = self.read_xml("server/ip")
            server_port = int(self.read_xml("server/port"))
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((server_ip, server_port))
            self.status_bar.config(text="已连接到服务器")
            self.show_login_dialog()
        except Exception as e:
            messagebox.showerror("连接失败", f"无法连接到服务器: {e}")
            self.root.quit()

    def show_login_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("登录")
        tk.Label(dialog, text="用户名:").grid(row=0)
        tk.Label(dialog, text="密码:").grid(row=1)
        self.username_entry = tk.Entry(dialog)
        self.password_entry = tk.Entry(dialog, show='*')
        self.username_entry.grid(row=0, column=1)
        self.password_entry.grid(row=1, column=1)
        login_btn = tk.Button(dialog, text="登录", command=self.login)
        login_btn.grid(row=2, columnspan=2)
        self.login_dialog = dialog

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        message = {
            'type': 'login',
            'data': {
                'username': username,
                'password': password
            }
        }
        self.send_message_to_server(message)
        self.login_dialog.destroy()
        self.root.deiconify()

    def send_message_to_server(self, message):
        if self.sock:
            try:
                self.sock.sendall(json.dumps(message).encode('utf-8') + b'\n')
            except Exception as e:
                print(f"发送失败: {e}")

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(1024).decode()
                if not data:
                    break
                messages = data.split('\n')
                for msg in messages:
                    if msg:
                        msg_dict = json.loads(msg)
                        if msg_dict.get('message'):
                            self.update_chat_display(msg_dict['message'])
            except Exception as e:
                print(f"接收消息错误: {e}")
                break

    def update_chat_display(self, message):
        self.msg_display.config(state=tk.NORMAL)
        self.msg_display.insert(tk.END, message + '\n')
        self.msg_display.config(state=tk.DISABLED)

    def send_message(self):
        message_content = self.input_box.get()
        self.input_box.delete(0, tk.END)
        target = self.contact_list.get(tk.ACTIVE)
        if target:
            message = {
                'type': 'message',
                'data': {
                    'target': target,
                    'message': message_content
                }
            }
        else:
            message = {
                'type': 'debugmessage',
                'data': message_content
            }
        self.send_message_to_server(message)

    def on_exit(self):
        if self.sock:
            self.sock.close()
        super().on_exit()
        sys.exit(0)


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
