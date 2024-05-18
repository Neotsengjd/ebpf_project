#!/usr/bin/python
# -*- coding: UTF-8 -*-
# 文件名：client.py

import socket               # 导入 socket 模块

s = socket.socket()         # 创建 socket 对象
port = 12345     # 设置端口号


s.connect(('127.0.0.1', port))
s.send(b"hi")
while True:
    try:
        print (s.recv(1024))
    except Exception as e:
        # This block handles any other exceptions
        print("An unexpected error occurred:", e)
        s.close()
        break
