#!usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2025/4/14
# @File    : database.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
import sqlite3
import traceback
import time


class Database:
    def __init__(self):
        self.conn = None
        self.cursor = None

    def connect(self, file):
        """建立数据库连接"""
        try:
            self.conn = sqlite3.connect(file , check_same_thread=False)
            self.cursor = self.conn.cursor()
        except sqlite3.Error as e:
            print(f"连接数据库失败: {e}")

    def run_sql(self, command, params=None):
        """执行 SQL 命令"""
        try:
            if params:
                self.cursor.execute(command, params)  # 参数化查询
            else:
                self.cursor.execute(command)
            self.conn.commit()  # 提交事务
        except sqlite3.Error as e:
            print(f"执行 SQL 失败: {e}")
            print(f"欲执行的SQL语句：{command}")
        return self.cursor.fetchall()

    def insert_sql(self, table, columns, values):
        """插入数据"""
        try:
            # 使用 ? 占位符代替直接拼接的 values
            placeholders = ",".join(["?"] * len(values))
            sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
            self.cursor.execute(sql, tuple(values))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"插入数据失败: {e}")
            print(traceback.format_exc())

    def select_sql(self, table, columns, condition=None):
        """查询数据"""
        try:
            sql = f"SELECT {columns} FROM {table}"
            if condition:
                sql += f" WHERE {condition}"
            result = self.run_sql(sql)
            return result
        except sqlite3.Error as e:
            print(f"查询数据失败: {e}")
            print(traceback.format_exc())
            return None

    def close(self):
        """关闭数据库连接"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def commit(self):
        if self.conn:
            self.conn.commit()


def add_account(username, password, name, register_time, database_file="server.sqlite"):
    """添加账号"""
    """register_time应为unix时间戳"""
    database = Database()
    database.connect(database_file)
    database.insert_sql("user", "username, password, name, register_time", [username, password, name, register_time])
    database.commit()
    database.close()


def delete_account(uid, database_file="server.sqlite"):
    """删除账号"""
    debug = False  # 是否删除数据库中的自增id
    database = Database()
    database.connect(database_file)
    database.run_sql("DELETE FROM user WHERE id=?", [uid])
    if debug:
        # 修复条件拼接问题，防止SQL注入
        user_id = database.select_sql("user", "id", f"id='{uid}'")
        if user_id:
            database.run_sql("UPDATE sqlite_sequence SET seq=? WHERE name='user'", [user_id[0][0] - 1])
    database.commit()
    database.close()


def change_account(uid, password, database_file="server.sqlite"):
    """修改账号"""
    database = Database()
    database.connect(database_file)
    database.run_sql("UPDATE user SET password=? WHERE id=?", [password, uid])
    database.commit()
    database.close()

def check_account_password(uid, password, database_file="server.sqlite"):
    database = Database()
    database.connect(database_file)
    result = database.select_sql("user", "*", f"id='{uid}'")
    database.commit()
    database.close()
    if result[0][2] == password:
        return True
    else:
        return False

def save_chat_history(message, from_user, to_user, database_file="server.sqlite"):
    database = Database()
    database.connect(database_file)
    database.insert_sql("chat_history", "content, from_user, to_user, type, send_time", [message, from_user, to_user, "text", time.time()])
    database.commit()
    database.close()

def get_uid_by_username(username, database_file="server.sqlite"):
    if database_file != "client.sqlite":
        database = Database()
        database.connect(database_file)
        result = database.select_sql("user", "id", f"username='{username}'")
        database.close()
        return result[0][0]
    else:
        database = Database()
        database.connect(database_file)
        result = database.select_sql("contact", "id", f"username='{username}'")
        if not result:
            return None
        database.close()
        return result[0][0]

def get_name_by_uid(uid, database_file="server.sqlite"):
    try:
        if database_file != "client.sqlite":
            database = Database()
            database.connect(database_file)
            result = database.select_sql("user", "name", f"id='{uid}'")
            database.commit()
            database.close()
            return result[0][0]
        else:
            database = Database()
            database.connect(database_file)
            result = database.select_sql("contact", "name", f"id='{uid}'")
            database.commit()
            database.close()
            return result[0][0]
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        print(result)
        return None

def save_contact(uid, username, name, mem, database_file="client.sqlite"):
    database = Database()
    database.connect(database_file)
    database.insert_sql("contact", "id, username, name, mem", [uid, username, name, mem])
    database.commit()
    database.close()

#----------------------------------------------------------------------

if __name__ == "__main__":
    db = Database()
    db.connect("server.sqlite")
    # 插入数据示例
    #add_account("kevin", "admin", "Kevin", time.time())
    # 查询数据示例
    query_result = db.select_sql("user", "*", "username='kevin'")
    print(query_result)
    #delete_account(db.select_sql("user", "id", "username='kevin'")[0][0])
    # 再次打印结果
    query_result = db.select_sql("user", "*", "username='kevin'")
    print(query_result)
    #save_chat_history("Hello, World!", "0", "0")
    #print(db.select_sql("chat_history", "*", "from_user='0'")) #[(1, '0', '0', 'text', 'Hello, World!', 1745759696.7458482)]
    save_contact("0",  "admin", "Kevin", "Kevin的账号")
    db.close()
    db.connect("client.sqlite")
    print(db.select_sql("contact", "*", "username='kevin'")) #[(0, 'admin', 'Kevin', 'Kevin的账号')]
    print(get_name_by_uid("0", "client.sqlite"))
    db.close()

