# -*- coding: utf-8 -*-
# @Time    : 2025/4/7
# @File    : server.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
import json
import socket
import sys
import threading
import tkinter as tk
import traceback
import time
from tkinter import ttk, messagebox
from xml.etree import ElementTree

import darkdetect
import sv_ttk
from plyer import notification

from GUI import GUI


class ClientApp(GUI):
    def __init__(self, root):
        super().__init__(root)
        self.username_entry = None
        self.password_entry = None
        self.login_dialog = None
        self.sock = None
        self.username = None
        self.current_selected_contact = None
        self.connect_to_server()
        self.contacts = self.read_contacts_from_xml()
        for contact in self.contacts:
            self.contact_list.insert(tk.END, contact)
        # 设置默认选择第一个用户
        if self.contacts:
            self.msg_display.pack_forget()
            self.contact_list.event_generate("<<ListboxSelect>>")
        self.root.bind('<Configure>', self.on_window_resize)
        threading.Thread(target=self.receive_messages, daemon=True).start()
        threading.Thread(target=self.a_unused_thread, daemon=True).start()

    @staticmethod
    def read_xml(keyword):
        try:
            tree = ElementTree.parse(r'data/client.xml')
            root = tree.getroot()
            return root.find(f".//{keyword}").text
        except AttributeError as e:
            raise ValueError(f"Keyword '{keyword}' not found in XML or invalid format.") from e

    @staticmethod
    def read_contacts_from_xml():
        try:
            tree = ElementTree.parse(r'data/client.xml')
            root = tree.getroot()
            contacts = [contact.text for contact in root.findall(".//contact/username")]
            return contacts
        except Exception as e:
            print(f"Error reading contacts from XML: {e}")
            print(traceback.format_exc())
            return []

    @staticmethod
    def read_chat_history_from_xml(username):
        """从XML文件中读取指定用户的聊天记录"""
        try:
            tree = ElementTree.parse(r'data/client.xml')
            root = tree.getroot()
            chat_node = root.find(f".//chatlog/chat[username='{username}']/chat")
            if chat_node is not None:
                chat_history = [msg.text for msg in chat_node.findall("message")]
                return chat_history
            return []
        except Exception as e:
            print(f"Error reading chat history from XML: {e}")
            print(traceback.format_exc())
            return []

    @staticmethod
    def save_chat_history_to_xml(message, username):
        """将聊天记录保存到XML文件，按用户名区分"""
        from xml.dom import minidom

        try:
            tree = ElementTree.parse(r'data/client.xml')
            root = tree.getroot()
            chat_node = root.find(f".//chatlog/chat[username='{username}']")
            if chat_node is None:
                chat_node = ElementTree.SubElement(root.find(".//chatlog"), "chat")
                username_node = ElementTree.SubElement(chat_node, "username")
                username_node.text = username
                chat_subnode = ElementTree.SubElement(chat_node, "chat")
            else:
                # 清空现有的聊天记录节点
                chat_subnode = chat_node.find("chat")
                for message_node in chat_subnode.findall("message"):
                    chat_subnode.remove(message_node)

            # 添加新的聊天记录

            message_node = ElementTree.SubElement(chat_subnode, "message")
            message_node.text = message

            # 格式化XML
            xml_str = ElementTree.tostring(root, encoding='utf-8')
            pretty_xml_str = minidom.parseString(xml_str).toprettyxml(indent="  ")

            # 去除多余的空行
            pretty_xml_str = '\n'.join([line for line in pretty_xml_str.split('\n') if line.strip()])

            with open(r'data/client.xml', 'w', encoding='utf-8') as f:
                f.write(pretty_xml_str)
        except Exception as e:
            print(f"Error saving chat history to XML: {e}")
            print(traceback.format_exc())

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
            print(traceback.format_exc())
            self.root.quit()

    def show_login_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("登录")
        ttk.Label(dialog, text="用户名:").grid(row=0)
        ttk.Label(dialog, text="密码:").grid(row=1)
        self.username_entry = ttk.Entry(dialog)
        self.password_entry = ttk.Entry(dialog, show='*')
        self.username_entry.grid(row=0, column=1)
        self.password_entry.grid(row=1, column=1)
        self.username_entry.insert(0, self.read_xml("account/username"))
        self.password_entry.insert(0, self.read_xml("account/password"))
        login_btn = ttk.Button(dialog, text="登录", command=self.login)
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
        self.username = username
        # 请求聊天记录
        threading.Thread(target=self.request_chat_history, daemon=True).start()
        self.root.deiconify()

    def send_message_to_server(self, message):
        if self.sock:
            try:
                self.sock.sendall(json.dumps(message).encode('utf-8') + b'\n')
                print(f"发送成功: {json.dumps(message) + '\n'}")
            except Exception as e:
                print(f"发送失败: {e}")
                print(traceback.format_exc())

    def update_chat_display(self, message, username):
        self.msg_display.config(state=tk.NORMAL)
        self.msg_display.insert(tk.END, message + '\n')
        self.msg_display.config(state=tk.DISABLED)
        # 保存聊天记录到XML，按用户名区分
        self.save_chat_history_to_xml(message, username)

    def request_chat_history(self):
        if self.sock:
            try:
                message = {
                    'type': 'get_chat_history',
                    'data': {
                        'username': self.username
                    }
                }
                self.send_message_to_server(message)
            except Exception as e:
                print(f"请求聊天记录失败: {e}")
                print(traceback.format_exc())

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(1024).decode()
                if not data:
                    break
                messages = data.split('\n')
                for message_data in messages:  # 将内部循环的变量名改为message_data
                    if message_data:
                        msg_dict = json.loads(message_data)
                        print(msg_dict)
                        # 修改解析逻辑
                        if msg_dict.get('type') == 'new_message':
                            target = msg_dict['data']['target']
                            print(target)
                            message_content = msg_dict['data']['message']
                            if target != 'system' and self.current_selected_contact == target:  # 仅当目标不是系统时才更新聊天显示
                                # 更新聊天显示
                                self.update_chat_display(f"{target}: {message_content}", target)
                            elif target != 'system' and self.current_selected_contact != target:
                                notification.notify(
                                    title=target,
                                    message=message_content,
                                    timeout=5,
                                    app_name='WritePapers'
                                )
                                self.save_chat_history_to_xml(message_content, target)
                            else:
                                # 处理系统消息
                                self.update_chat_display(f"system: {message_content}", 'system')
                                notification.notify(
                                    title='system',
                                    message=message_content,
                                    timeout=3,
                                    app_name='WritePapers'
                                )
                        elif msg_dict.get('type') == 'error_message':
                            message_content = msg_dict['message']
                            print(f"Error message: {message_content}")
                            sys.exit(1)
                        elif msg_dict.get('type') == 'chat_history':
                            chat_data = msg_dict['data']
                            username = chat_data['username']
                            chat_history = chat_data['history']
                            # 保存聊天记录到XML
                            for msg in chat_history:
                                self.save_chat_history_to_xml(msg.split(': ')[1] + ":" + msg.split(': ')[2], msg.split(':')[0])
            except Exception as e:
                print(f"接收消息错误: {e}")
                print(traceback.format_exc())
                break

    def a_unused_thread(self):
        while True:
            if self.sock:
                self.status_bar.config(text=f"已连接到服务器")
                time.sleep(2)
            self.status_bar.config(text=f"{self.username}")
            time.sleep(2)

    def on_contact_select(self, event):
        if not self.msg_display.winfo_ismapped():
            self.msg_display.pack(side=tk.LEFT, fill=tk.BOTH)
        # 获取选中的用户
        selected_index = self.contact_list.curselection()
        if selected_index:
            selected_user = self.contacts[selected_index[0]]
            self.current_selected_contact = selected_user
            # 加载并显示选中用户的聊天记录
            chat_history = self.read_chat_history_from_xml(selected_user)
            self.msg_display.config(state=tk.NORMAL)
            self.msg_display.delete('1.0', tk.END)
            for msg in chat_history:
                self.msg_display.insert(tk.END, msg + '\n')
            self.msg_display.config(state=tk.DISABLED)
        str(event)

    def on_window_resize(self, event):
        self.contact_list.config(height=int(self.root.winfo_height() * 0.046))
        self.msg_display.config(height=int(self.root.winfo_height() * 0.046), width=int(self.root.winfo_width() * 0.7))
        str(event)

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
            self.update_chat_display(f"{self.username}: {message_content}", target)  # 按用户名更新聊天记录
        else:
            message = {
                'type': 'debugmessage',
                'data': message_content
            }
        self.send_message_to_server(message)
        # self.save_chat_history_to_xml(message=f"{message_content}", username=target)

    def on_exit(self):
        if self.sock:
            self.sock.close()
        super().on_exit()
        sys.exit(0)


def main():
    root = tk.Tk()
    app = ClientApp(root)
    # 绑定列表框选择事件
    app.contact_list.bind('<<ListboxSelect>>', app.on_contact_select)
    sv_ttk.set_theme(darkdetect.theme())
    root.mainloop()


if __name__ == "__main__":
    main()
