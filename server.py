# -*- coding: utf-8 -*-
# @Time    : 2025/4/7
# @File    : server.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
import socket
import threading
import xml.etree.ElementTree as ElementTree
import json
import sys
from threading import Lock

# 全局变量：存储所有在线客户端的连接
clients = []
# 全局变量：存储已登录的客户端
logged_in_clients = {}
# 线程锁，用于保护对全局变量的访问
lock = Lock()


def read_xml(keyword):
    try:
        tree = ElementTree.parse(r'data/server.xml')
        root = tree.getroot()
        return root.find(f".//{keyword}").text
    except AttributeError as e:
        raise ValueError(f"Keyword '{keyword}' not found in XML or invalid format.") from e


def read_accounts():
    tree = ElementTree.parse(r'data/server.xml')
    root = tree.getroot()
    accounts = {}
    for account in root.findall(".//account"):
        username = account.find("username").text
        password = account.find("password").text
        accounts[username] = password
    return accounts


def send_message(message, conn):
    conn.sendall(json.dumps(message).encode("utf-8") + b"\n")


def handle_client(conn, addr):
    global logged_in_clients  # 显式声明使用全局变量
    print(f"New connection from {addr}")
    while True:
        try:
            data = conn.recv(1024).decode()
            if not data:
                break
            print(f"Received: {data}")
            message = json.loads(data)
            # 处理客户端发来的消息
            if message['type'] == "login":
                username = message['data']['username']
                password = message['data']['password']
                # 验证用户名密码
                accounts = read_accounts()
                if username in accounts and accounts[username] == password:
                    with lock:  # 使用锁保护全局变量
                        if username in logged_in_clients:
                            send_message({"type": "warning_message", "message": "Already logged in"}, conn)
                            conn.close()
                            clients.remove(conn)
                            del logged_in_clients[username]  # 使用del删除已登录的客户端
                            print(f"Connection closed with {addr} due to repeated login attempt")
                            return
                        else:
                            print(f"Login successful for {username}")
                            send_message({"type": "server_message", "message": "Login successful"}, conn)
                            print("Send:" + json.dumps({"type": "server_message", "message": "Login successful"}))
                            logged_in_clients[username] = conn
                            continue
                else:
                    print(f"Login failed for {username}")
                    send_message({"type": "error_message", "message": "Login failed"}, conn)
                    conn.close()
                    clients.remove(conn)
                    del logged_in_clients[username]  # 使用del删除已登录的客户端
                    print(f"Connection closed with {addr}")
                    return
            elif message['type'] == "debugmessage":  # 对debugmessage类型的处理
                username = None
                for user, client_conn in logged_in_clients.items():
                    if client_conn == conn:
                        username = user
                        break
                if username is None:
                    send_message({"type": "error_message", "message": "Please log in first"}, conn)
                    continue
                # 广播消息给所有客户端，包括发送方客户端
                for client_conn in clients:
                    send_message({"message": f"{username}: {message['data']}"}, client_conn)
            elif message['type'] == "message":  # 处理私信消息
                target = message['data']['target']
                whisper_message = message['data']['message']
                username = None
                for user, client_conn in logged_in_clients.items():
                    if client_conn == conn:
                        username = user
                        break
                if username is None:
                    send_message({"type": "error_message", "message": "Please log in first"}, conn)
                    continue
                target_conn = logged_in_clients.get(target)
                if target_conn:
                    message_content = f"Message from {username}: {whisper_message}"
                    send_message({"type": "new_message", "message": message_content}, target_conn)
                    send_message({"type": "server_message", "message": "Message sent"}, conn)
                else:
                    send_message({"type": "error_message", "message": "Target user not found"}, conn)
        except Exception as e:
            print(f"Error handling client: {e}")
            send_message({"type": "error_message", "message": "An error occurred on the server"}, conn)
            break
    with lock:  # 使用锁保护全局变量
        conn.close()
        clients.remove(conn)
        logged_in_clients = {k: v for k, v in logged_in_clients.items() if v != conn}
    print(f"Connection closed with {addr}")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((read_xml("server/ip"), int(read_xml("server/port"))))
    server.listen()
    print("Server started, waiting for connections...")

    while True:
        conn, addr = server.accept()
        clients.append(conn)
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        for client in clients:
            client.close()
            clients.remove(client)
            logged_in_clients.clear()
        sys.exit(0)
