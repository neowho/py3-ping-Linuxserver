# SaoMiao_Ping

并发 Ping 工具。Python 3.12 源码使用 asyncio 和 icmplib 直接发送 ICMP，每台 4 个包。窗口程序是 `SaoMiao_Ping.exe`。

## 1. 开源协议

Apache License 2.0

本工具的源代码和随附文档按 Apache License 2.0 授权。完整条款见同目录的 [LICENSE](LICENSE)。

## 2. 源码运行方式

需要 Python 3.12（64 位，安装时包含 tcl/tk）。在本目录打开终端后执行：

```text
py -3 -m pip install icmplib
py -3 SaoMiao_Ping.py
```

只检测你有权检测的服务器。源码不调用 `ping.exe`，也不调用 `nmap.exe`。

## 3. 下载地址

[转到 SaoMiao_Ping Releases](https://github.com/SaoMiaoCeShi/SaoMiao_Ping/releases)

从 Releases 下载 `SaoMiao_Ping.exe`。本目录里的 `SaoMiao_Ping.exe` 与当前 `SaoMiao_Ping.py` 是同一次 Python 3.12 打包结果。

## 4. 系统依赖

- 系统：Windows 10 或 Windows 11，64 位。
- `SaoMiao_Ping.exe` 需要 Microsoft Visual C++ 2015–2022 运行库（x64）。没有这个运行库时，exe 可能无法启动。下载地址：https://aka.ms/vs/17/release/vc_redist.x64.exe。说明页：[最新支持的 Visual C++ 可再发行组件](https://learn.microsoft.com/zh-cn/cpp/windows/latest-supported-vc-redist)。
- 源码运行需要 Python 3.12 和 `icmplib`。官方 Python 安装程序请从 [python.org](https://www.python.org/downloads/windows/) 选择 Windows installer（64-bit），不要使用不含 tkinter 的嵌入式包。
- ICMP 原始套接字若被系统拒绝，请用管理员身份重新打开程序。
