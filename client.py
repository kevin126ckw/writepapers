#!/usr/bin/python
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
import database
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
        self.db = database.Database()
        self.db.connect("client.sqlite")
        self.contacts = self.read_contacts_from_xml()
        for contact in self.contacts:
            self.contact_list.insert(tk.END, contact[3])
        # 设置默认选择第一个用户
        if self.contacts:
            self.msg_display.pack_forget()
            self.contact_list.event_generate("<<ListboxSelect>>")
        self.root.bind('<Configure>', self.on_window_resize)
        threading.Thread(target=self.receive_messages, daemon=True).start()
        threading.Thread(target=self.a_unused_thread, daemon=True).start()

    def save_chat_history_to_xml(self, message, from_user, to_user):
        """将聊天记录保存到db"""

        try:
            self.db.insert_sql("chat_history", "content, from_user, to_user, type, send_time", [message, from_user, to_user, "text", time.time()])
        except Exception as e:
            print(f"Error saving chat history to XML: {e}")
            print(traceback.format_exc())

    @staticmethod
    def read_xml(keyword):
        try:
            tree = ElementTree.parse(r'data/client.xml')
            root = tree.getroot()
            return root.find(f".//{keyword}").text
        except AttributeError as e:
            raise ValueError(f"Keyword '{keyword}' not found in XML or invalid format.") from e

    def read_chat_history_from_db(self, username):
        """从db中读取指定用户的聊天记录"""
        try:
            chat_history = []
            result = self.db.select_sql("chat_history", "*", f"from_user='{database.get_uid_by_username(username, database_file="client.sqlite")}'")
            print(result)
            if result is None or result == []:
                return []
            for row in result:
                chat_history.append({
                    "id": row[0],
                    "from_user": row[1],
                    "to_user": row[2],
                    "type": row[3],
                    "content": row[4],
                    "send_time": row[5]
                })
            return chat_history
        except Exception as e:
            print(f"Error reading chat history from XML: {e}")
            print(traceback.format_exc())
            return []
    def read_contacts_from_xml(self):
        try:
            contacts = self.db.select_sql("contact", "*")
            return contacts
        except Exception as e:
            print(f"Error reading contacts from db: {e}")
            print(traceback.format_exc())
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

    def update_chat_display(self, message, from_user, to_user):
        self.msg_display.config(state=tk.NORMAL)

        self.msg_display.insert(tk.END, database.get_name_by_uid(from_user, database_file="client.sqlite") + ": " + message + '\n')
        self.msg_display.config(state=tk.DISABLED)
        self.save_chat_history_to_xml(message, from_user,  to_user)

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
                    print(f"Received: {message_data}")
                    if message_data:
                        msg_dict = json.loads(message_data)
                        print(msg_dict)
                        # 修改解析逻辑
                        if msg_dict.get('type') == 'new_message':
                            target = msg_dict['data']['target']
                            print("-------",target)
                            message_content = str(msg_dict['data']['message'])
                            if target != '9999' and database.get_uid_by_username(self.current_selected_contact, database_file="client.sqlite") == target:  # 仅当目标不是系统时才更新聊天显示
                                # 更新聊天显示
                                self.update_chat_display(f"{message_content}", target, database.get_uid_by_username(self.username, database_file="client.sqlite"))
                            elif target != '9999' and database.get_uid_by_username(self.current_selected_contact, database_file="client.sqlite") != target:
                                notification.notify(
                                    title=database.get_name_by_uid(target, database_file="client.sqlite"),
                                    message=message_content,
                                    timeout=5,
                                    app_name='WritePapers'
                                )
                                self.save_chat_history_to_xml(message_content, database.get_uid_by_username(target, database_file="client.sqlite"), database.get_uid_by_username(self.username, database_file="client.sqlite"))
                            else:
                                # 处理系统消息
                                self.update_chat_display(f"system: {message_content}", '9999', database.get_uid_by_username(self.username, database_file="client.sqlite"))
                                notification.notify(
                                    title='System',
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
                            for msg in chat_history:
                                try:
                                    target = msg.get("target", "unknown")
                                    # message_id = msg.get("id", "unknown")
                                    content = msg.get("content", "unknown")
                                    self.save_chat_history_to_xml(f"{content}", username, target)
                                    print(f"save chat history to xml:{content}", username, target)
                                except Exception as e:
                                    print(f"Error parsing chat history message: {e}")

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
            selected_user = self.contacts[selected_index[0]][1]
            print(f"Selected user: {selected_user}")
            self.current_selected_contact = selected_user
            # 加载并显示选中用户的聊天记录
            chat_history = self.read_chat_history_from_db(selected_user)
            print(chat_history)
            self.msg_display.config(state=tk.NORMAL)
            self.msg_display.delete('1.0', tk.END)
            for msg in chat_history:
                print(f"Loading chat history for {selected_user}: {msg}")
                # 将字典格式的消息转换为字符串
                msg_str = f"{database.get_name_by_uid(msg['from_user'], database_file="client.sqlite")}: {msg['content']}"
                self.msg_display.insert(tk.END, msg_str + '\n')
            self.msg_display.config(state=tk.DISABLED)
        str(event)

    def on_window_resize(self, event):
        self.contact_list.config(height=int(self.root.winfo_height() * 0.046))
        self.msg_display.config(height=int(self.root.winfo_height() * 0.046), width=int(self.root.winfo_width() * 0.7))
        str(event)

    def send_message(self):
        message_content = self.input_box.get()
        self.input_box.delete(0, tk.END)
        target = self.current_selected_contact
        if target:
            message = {
                'type': 'message',
                'data': {
                    'target': target,
                    'message': message_content
                }
            }
            self.update_chat_display(f"{message_content}", database.get_uid_by_username(self.username, database_file="client.sqlite"), database.get_uid_by_username(target, database_file="client.sqlite"))  # 按用户名更新聊天记录
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

    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("KeyboardInterrupt received. Exiting...")
        if app.sock:
            app.sock.close()
        app.on_exit()
        sys.exit(0)


if __name__ == "__main__":
    main()
