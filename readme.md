# Mitmproxy GUI

一个基于 Mitmproxy 的图形化代理工具，支持多种加密算法的请求拦截和修改。本项目提供了一个直观的图形界面，使得使用 mitmproxy 进行请求拦截和加解密变得更加简单。

## 功能特点

- 🖥️ 图形化界面，操作简单直观
- 🔐 支持多种加密算法：
  - RSA 非对称加密
  - DES (ECB/CBC) 对称加密
  - AES (ECB/CBC/GCM) 对称加密
  - Base64 编码/解码
- 🔄 支持三种工作模式：
  - 加密模式
  - 解密模式
  - 双向模式（同时支持加密和解密）
- 📝 支持多种数据格式：
  - JSON 数据
  - 表单数据 (x-www-form-urlencoded)
- 📊 实时显示请求详情和日志
- 🔢 支持多字段同时加解密
- 🔌 支持自定义上游代理
- 📁 自动保存加解密日志

## 系统要求

- Python 3.8+
- Windows/macOS/Linux

## 安装步骤

1. 克隆仓库：

```bash
git clone https://github.com/blackguest007/mitmproxy-gui.git
cd mitmproxy-gui
```

2. 创建虚拟环境（推荐）：

```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. 安装依赖：

```bash
pip install -r requirements.txt
```

## 快速开始

1. 启动程序：

```bash
cd src
python main.py
```

2. 基本设置：
   - 选择工作模式（加密/解密/双向）
   - 选择加密算法
   - 设置监听端口（默认 8888）
   - 设置上游代理端口（默认 8080）
   - 输入需要处理的字段名（多个字段用逗号分隔）
   - 输入密钥和 IV（如果需要）

## 详细使用说明

### 工作模式

#### 加密模式

- 监听指定端口
- 对请求数据进行加密处理
- 支持的数据格式：
  - application/json
  - application/x-www-form-urlencoded

#### 解密模式

- 监听指定端口
- 对请求数据进行解密处理
- 自动转发到上游代理

#### 双向模式

- 同时启动加密和解密代理
- 支持请求数据的实时加解密
- 自动处理上下游代理转发

### 支持的加密算法

#### RSA

- 支持公钥加密/私钥解密
- 支持 .pem 格式密钥文件
- 支持 Base64 格式密钥

#### DES

- 支持 ECB/CBC 模式
- 支持自定义 IV（CBC 模式）
- 支持 PKCS7 填充

#### AES

- 支持 ECB/CBC/GCM 模式
- 支持自定义 IV（CBC/GCM 模式）
- 支持 PKCS7 填充
- GCM 模式支持认证标签

#### Base64

- 支持标准 Base64 编码/解码
- 支持 URL 安全的 Base64 编码/解码

## 项目结构

```
mitmproxy-gui/
├── src/                    # 源代码目录
│   ├── main.py            # 主程序入口
│   ├── ui/                # 用户界面相关代码
│   ├── core/              # 核心功能实现
│   ├── controllers/       # 控制器
│   └── utils/             # 工具函数
├── scripts/               # 脚本目录
│   └── decryptTools/      # 解密工具
│       ├── aes_gcm.py     # AES-GCM 实现
│       ├── aes_cbc.py     # AES-CBC 实现
│       ├── aes_ecb.py     # AES-ECB 实现
│       ├── des_cbc.py     # DES-CBC 实现
│       ├── des_ecb.py     # DES-ECB 实现
│       ├── rsa.py         # RSA 实现
│       └── base64.py      # Base64 实现
├── logs/                  # 日志目录
├── resource/              # 资源文件
└── requirements.txt       # 项目依赖
```

## 日志说明

- 日志文件保存在 `logs` 目录下
- 加密日志格式：`encrypt_算法名_时间戳.log`
- 解密日志格式：`decrypt_算法名_时间戳.log`
- 日志内容包括：
  - 时间戳
  - 请求 URL
  - 处理字段
  - 原始值
  - 处理后的值

## 常见问题

1. 证书问题

   - 首次使用需要安装 mitmproxy 证书
   - 在浏览器中访问 mitm.it 下载并安装证书

2. 端口占用

   - 确保设置的端口未被其他程序占用
   - 可以修改默认端口（8888/8080）

3. 加解密失败
   - 检查密钥和 IV 是否正确
   - 确认数据格式是否符合要求
   - 查看日志文件了解详细错误信息

## 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进项目。

## 许可证

MIT License

## 联系方式

如有问题或建议，请提交 Issue 或联系项目维护者。
