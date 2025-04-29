#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2025/4/7
# @File    : server.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
import socket
import threading
import traceback
import xml.etree.ElementTree as ElementTree
import json
import sys
import time
import database
from threading import Lock

# 全局变量：数据库对象
db = database.Database()
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


def save_chat_history(message, from_user, to_user):
    """将聊天记录保存到数据库，按UID区分"""
    try:
        db.connect("server.sqlite")
        # 使用转义后的列名 "[from]" 和 "[to]"
        db.insert_sql(
            "chat_history",
            "[content], [from_user], [to_user], [type], [send_time]",
            [message, from_user, to_user, "text", time.time()]
        )
        db.close()
    except Exception as e:
        print(f"Error saving chat history to db: {e}")
        print(traceback.format_exc())



def read_chat_history_from_xml(from_user):
    """从数据库中读取指定用户的聊天记录"""
    try:
        chat_history = []
        print(f"Reading chat history from db,from_user:{from_user}")
        if isinstance(from_user, int):
            results = db.select_sql("chat_history", "*", f"from_user='{from_user}'")
        else:
            results = db.select_sql("chat_history", "*", f"from_user='{database.get_uid_by_username(from_user)}'")
        if results is None or not results:
            return []
        for row in results:
            chat_history.append({
                "uid": row[0],
                "message": row[1],
                "from": row[2],
                "to": row[3],
                "type": row[4],
                "send_time": row[5]
            })
        return chat_history
    except Exception as e:
        print(f"Error reading chat history from database: {e}")
        print(traceback.format_exc())
        return []



def send_message(message, conn):
    conn.sendall(json.dumps(message).encode("utf-8") + b"\n")
    print("Send:" + json.dumps(message) + "\n")

def get_user_uid(username):
    print(f"Getting uid by username from db {username}")
    return database.get_uid_by_username(username)

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
            if message['type'] == "login":
                username = message['data']['username']
                password = message['data']['password']
                # 验证用户名密码
                if database.check_account_password(get_user_uid(username), password):
                    with lock:  # 使用锁保护全局变量
                        if username in logged_in_clients:
                            send_message({"type": "error_message", "message": "Already logged in"}, conn)
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
                if username == "admin":
                    # 广播消息给所有客户端，包括发送方客户端
                    for client_conn in clients:
                        send_message({"message": f"{username}: {message['data']}"}, client_conn)
                else:
                    send_message({"type": "warning_message", "message": "You are not admin"}, conn)
            elif message['type'] == "message":  # 处理私信消息
                to_user = message['data']['target']
                whisper_message = message['data']['message']
                from_user = None
                for user, client_conn in logged_in_clients.items():
                    if client_conn == conn:
                        from_user = user
                        break
                if from_user is None:
                    send_message({"type": "error_message", "message": "Please log in first"}, conn)
                    continue
                target_conn = logged_in_clients.get(to_user)
                if target_conn:
                    message_content = {"type": "new_message", "data": {"target": get_user_uid(from_user), "message": whisper_message}}
                    send_message(message_content, target_conn)
                    send_message({"type": "server_message", "message": "Message sent"}, conn)
                    save_chat_history(whisper_message, get_user_uid(from_user), get_user_uid(to_user))
                else:
                    send_message({"type": "warning_message", "message": "Target user not online"}, conn)
                    save_chat_history(whisper_message, get_user_uid(from_user), get_user_uid(to_user))
            # 处理客户端发来的消息
            elif message['type'] == "get_chat_history":  # 处理获取聊天记录的消息
                from_user = message['data']['username']
                chat_history = read_chat_history_from_xml(get_user_uid(from_user))
                print(f"Chat history for {from_user}: {chat_history}")
                # 修改返回的聊天记录格式，包含用户名、聊天对象和消息ID
                send_message({"type": "chat_history", "data": {"username": from_user, "history": chat_history}}, conn)
        except Exception as e:
            print(f"Error handling client: {e}")
            send_message({"type": "warning_message", "message": "An error occurred on the server"}, conn)
            print(traceback.format_exc())
            break
    with lock:  # 使用锁保护全局变量
        conn.close()
        clients.remove(conn)
        logged_in_clients = {k: v for k, v in logged_in_clients.items() if v != conn}
    print(f"Connection closed with {addr}")


def main():
    db.connect("server.sqlite")
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
        db.close()
        sys.exit(0)
