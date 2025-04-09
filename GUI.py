import tkinter as tk
from tkinter import ttk, messagebox


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WritePapers 聊天客户端")
        self.root.geometry("800x600")

        # 创建菜单栏
        menubar = tk.Menu(root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="退出", command=self.on_exit)
        menubar.add_cascade(label="文件", menu=file_menu)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)
        root.config(menu=menubar)

        # 左侧联系人列表
        self.contact_frame = tk.Frame(root)
        self.contact_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.contact_list = tk.Listbox(self.contact_frame)
        self.contact_list.config(height=20)
        self.contact_list.pack(side=tk.TOP, fill=tk.BOTH, padx=5, pady=5)

        # 状态栏
        self.status_bar = ttk.Label(self.contact_frame, text="在线状态：正在连接...", padding="5")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)  # 将状态栏放在左侧联系人列表底部

        # 右侧聊天区域
        self.chat_frame = ttk.Frame(root, padding="5")
        self.chat_frame.pack(side=tk.RIGHT, expand=1, fill=tk.BOTH)

        # 聊天显示区域
        self.msg_display = tk.Text(self.chat_frame, state=tk.DISABLED)
        self.msg_display.pack(side=tk.TOP, expand=1, fill=tk.BOTH, padx=5, pady=5)

        # 输入框区域
        input_frame = ttk.Frame(self.chat_frame, padding="5")
        input_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.input_box = ttk.Entry(input_frame, width=50)
        self.input_box.pack(side=tk.LEFT, expand=1, fill=tk.X, padx=5)
        send_btn = ttk.Button(input_frame, text="发送", command=self.send_message)
        send_btn.pack(side=tk.RIGHT, padx=5, pady=5)

        self.root.withdraw()

    def on_exit(self):
        """菜单退出按钮绑定函数"""
        pass

    @staticmethod
    def show_about():
        """关于对话框"""
        messagebox.showinfo("关于", "WritePapers聊天客户端 V1.0")

    def send_message(self):
        """发送消息按钮绑定函数"""
        pass