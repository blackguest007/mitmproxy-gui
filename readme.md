# Mitmproxy GUI

一个基于 Mitmproxy 的 GUI 工具，支持多种加密算法的请求拦截和修改。

## 功能特点

- 图形化界面，操作简单直观
- 支持多种加密算法：
  - RSA
  - DES (ECB/CBC)
  - AES (ECB/CBC)
  - Base64
- 支持三种工作模式：
  - 加密模式
  - 解密模式
  - 双向模式（同时支持加密和解密）
- 支持 JSON 和表单数据的处理
- 实时显示请求详情和日志
- 支持多字段同时加解密
- 支持自定义上游代理

## 安装要求

- Python 3.8+
- PyQt6
- mitmproxy 9.0+
- pycryptodome

## 快速开始

1. 安装依赖：

bash

pip install -r requirements.txt



## 使用说明



进入 src 目录

```python
python main.py
```



### 基本设置

1. 选择工作模式（加密/解密/双向）
2. 选择加密算法
3. 设置监听端口（默认 8888）
4. 设置上游代理端口（默认 8080）
5. 输入需要处理的字段名（多个字段用逗号分隔）
6. 输入密钥和 IV（如果需要）

![image-20250314154401242](/Users/lingdu/Library/Application Support/typora-user-images/image-20250314154401242.png)

![image-20250314154438533](/Users/lingdu/Library/Application Support/typora-user-images/image-20250314154438533.png)

### 加密模式

- 监听指定端口
- 对请求数据进行加密处理
- 支持的数据格式：
  - application/json
  - application/x-www-form-urlencoded

### 解密模式

- 监听指定端口
- 对请求数据进行解密处理
- 自动转发到上游代理

### 双向模式

- 同时启动加密和解密代理
- 支持请求数据的实时加解密
- 自动处理上下游代理转发

## 支持的加密算法

### RSA

- 支持公钥加密/私钥解密
- 支持 .pem 格式密钥文件
- 支持 Base64 格式密钥

### DES

- 支持 ECB/CBC 模式
- 支持自定义 IV（CBC 模式）
- 支持 PKCS7 填充

### AES

- 支持 ECB/CBC 模式
- 支持自定义 IV（CBC 模式）
- 支持 PKCS7 填充

### Base64

- 支持标准 Base64 编码/解码
- 支持 URL 安全的 Base64 编码/解码

## 项目结构

## 使用说明

### 基本设置

1. 选择工作模式（加密/解密/双向）
2. 选择加密算法
3. 设置监听端口（默认 8888）
4. 设置上游代理端口（默认 8080）
5. 输入需要处理的字段名（多个字段用逗号分隔）
6. 输入密钥和 IV（如果需要）

### 加密模式

- 监听指定端口
- 对请求数据进行加密处理
- 支持的数据格式：
  - application/json
  - application/x-www-form-urlencoded

### 解密模式

- 监听指定端口
- 对请求数据进行解密处理
- 自动转发到上游代理

### 双向模式

- 同时启动加密和解密代理
- 支持请求数据的实时加解密
- 自动处理上下游代理转发

## 支持的加密算法

### RSA

- 支持公钥加密/私钥解密
- 支持 .pem 格式密钥文件
- 支持 Base64 格式密钥

### DES

- 支持 ECB/CBC 模式
- 支持自定义 IV（CBC 模式）
- 支持 PKCS7 填充

### AES

- 支持 ECB/CBC 模式
- 支持自定义 IV（CBC 模式）
- 支持 PKCS7 填充

### Base64

- 支持标准 Base64 编码/解码
- 支持 URL 安全的 Base64 编码/解码

## 项目结构
