# -*- coding: utf-8 -*-  # 源码编码
# SaoMiao_Ping  # 单独的并发 Ping 程序，不包含 Nmap 窗口
# Python 3.12  # 使用 asyncio 调度批量探测
# 发包使用 icmplib，不调用 ping.exe  # 每台固定发送 4 个 ICMP 回显请求
# 界面仍是黑白 tkinter  # 左侧增加可粘贴的多行地址框
import asyncio  # 并发等待多台 ICMP 回复
import os  # 程序目录、列表文件和报告目录
import platform  # 把系统名称写入报告
import queue  # 后台结果送回界面
import re  # 拆分地址并识别旧结论里的 TTL
import shutil  # 兼容旧结果窗口查找 ping.exe
import subprocess  # 兼容旧结果窗口启动 ping.exe
import sys  # 区分源码和打包后的 exe
import threading  # 在界面外运行 asyncio
import time  # 报告时间
import traceback  # 未捕获异常写入日志

import tkinter as tk  # 标准库窗口
import tkinter.font as tkfont  # 选择中文字体
from tkinter import filedialog  # 选择列表文件
from tkinter import messagebox  # 输入和保存提示
from icmplib import async_ping  # 纯代码发送 ICMP
from icmplib.exceptions import ICMPSocketError, SocketPermissionError  # 套接字失败时给出原因

VERSION = "2.1.0"  # 右侧红绿灯结果版本
BLACK = "#000000"  # 黑色
WHITE = "#FFFFFF"  # 白色
GREEN = "#1B8A1B"  # Ping 通的绿色圆灯
RED = "#D21F1F"  # 未 Ping 通的红色圆灯
GRAY = "#8A8A8A"  # 还没有结果时的灰灯
LAMP_WAIT = "wait"  # 等待探测
LAMP_UP = "up"  # 已经 Ping 通
LAMP_DOWN = "down"  # 未 Ping 通
MAX_IPS = 5000  # 列表上限
MAX_MENU_ITEMS = 500  # 下拉菜单最多列出的地址
MAX_LIST_BYTES = 2 * 1024 * 1024  # 列表文件上限 2MB
MAX_RANGE = 512  # 连续网段一次最多的地址数
PING_COUNT = 4  # 每台固定发送 4 个包
PING_INTERVAL = 0.2  # 同一台两个包之间的秒数
PING_TIMEOUT = 1.0  # 每个包最多等待 1 秒
PING_CONCURRENCY = 80  # 同时探测的地址数
SINGLE_COUNT = 2  # 旧结果窗口仍按 2 次调用系统 ping.exe
SINGLE_WAIT = 1000  # 旧结果窗口的等待毫秒数
BATCH_COUNT = 2  # 保留旧常量，新界面不再使用
BATCH_WAIT = 800  # 保留旧常量，新界面不再使用


def app_base_dir():  # 源码目录或 exe 所在目录
    if getattr(sys, "frozen", False):  # 打包后的程序
        return os.path.dirname(os.path.abspath(sys.executable))  # exe 目录
    return os.path.dirname(os.path.abspath(__file__))  # 源码目录


def is_ipv4(value):  # 只接受没有前导零的 IPv4
    if not isinstance(value, str):  # 非文字直接拒绝
        return False  # 无效
    parts = value.strip().split(".")  # 按点分成四段
    if len(parts) != 4:  # 必须正好四段
        return False  # 无效
    for part in parts:  # 逐段检查
        if not part or any(ch < "0" or ch > "9" for ch in part):  # 只允许数字
            return False  # 无效
        if len(part) > 1 and part.startswith("0"):  # 拒绝 01 这种写法
            return False  # 无效
        number = int(part)  # 转成整数
        if number < 0 or number > 255:  # 超出单段范围
            return False  # 无效
    return True  # 四段都合法


def split_ip_text(text):  # 把一行里的多个地址拆开
    if not isinstance(text, str):  # 没有文字
        return []  # 空列表
    pieces = re.split(r"[\s,;，；、|&]+", text.strip())  # 空白和常见分隔符都切开
    result = []  # 非空片段
    for piece in pieces:  # 去掉空片段
        if piece:  # 有内容才保留
            result.append(piece)  # 加入结果
    return result  # 返回片段


def parse_ip_tokens(text):  # 分开合法地址和无效文字
    valids = []  # 合法地址
    invalids = []  # 只记录、不探测的文字
    for token in split_ip_text(text):  # 逐个片段
        if is_ipv4(token):  # 合法 IPv4
            valids.append(token)  # 可以探测
        else:  # 主机名或命令文字
            invalids.append(token)  # 记入日志
    return valids, invalids  # 两类一起返回


def parse_ip_lines(text):  # 多行文本，每行一个地址，重复地址只保留第一次
    valids = []  # 按出现顺序保存
    invalids = []  # 无效行里的文字
    seen = set()  # 已经收下的地址
    if not isinstance(text, str):  # 没有文本
        return valids, invalids  # 空结果
    for raw in text.splitlines():  # 竖着一行一行看
        line = raw.split("#", 1)[0].strip()  # 井号后面当作注释
        if not line:  # 空行跳过
            continue  # 下一行
        good, bad = parse_ip_tokens(line)  # 这一行里的地址
        invalids.extend(bad)  # 无效文字留到日志
        for ip in good:  # 这一行的合法地址
            if ip in seen:  # 框里重复粘贴
                continue  # 不探测第二次
            seen.add(ip)  # 记住
            valids.append(ip)  # 保留顺序
    return valids, invalids  # 返回两类


def ipv4_int(ip):  # 把地址变成可比较的整数
    numbers = [int(part) for part in ip.split(".")]  # 四段已经校验过
    return (numbers[0] << 24) + (numbers[1] << 16) + (numbers[2] << 8) + numbers[3]  # 32 位数值


def int_to_ipv4(number):  # 把整数还原成地址
    return "{}.{}.{}.{}".format((number >> 24) & 255, (number >> 16) & 255, (number >> 8) & 255, number & 255)  # 四段十进制


def expand_ipv4_range(start, end, limit):  # 展开连续地址，超过上限就拒绝
    if not is_ipv4(start) or not is_ipv4(end):  # 起止都要合法
        raise ValueError("起始IP和结束IP都要是有效 IPv4")  # 交给界面
    left = ipv4_int(start)  # 起点
    right = ipv4_int(end)  # 终点
    if left > right:  # 不自动对调
        raise ValueError("起始IP要小于或等于结束IP")  # 提示调整
    count = right - left + 1  # 含首尾
    if count > limit:  # 一次不能太大
        raise ValueError("这一段有 {} 个地址，超过 {} 个上限".format(count, limit))  # 说明数量
    hosts = []  # 结果
    current = left  # 从起点开始
    while current <= right:  # 直到终点
        hosts.append(int_to_ipv4(current))  # 还原成文字
        current += 1  # 下一个地址
    return hosts  # 完整网段


def expand_last_octet(ip, first, last, limit):  # 用前三段展开最后一段
    if not is_ipv4(ip):  # 基准地址必须合法
        raise ValueError("请在起始IP填写这个网段中的一个地址")  # 提示位置
    if first < 1 or last > 254 or first > last:  # 不包含 0 和 255
        raise ValueError("网段最后一段无效")  # 拒绝
    parts = ip.split(".")  # 前三段
    start = "{}.{}.{}.{}".format(parts[0], parts[1], parts[2], first)  # 起点
    end = "{}.{}.{}.{}".format(parts[0], parts[1], parts[2], last)  # 终点
    return expand_ipv4_range(start, end, limit)  # 复用上限检查


def describe_ping(host):  # 把 icmplib 的结果写成界面文字
    sent = int(host.packets_sent)  # 实际发出的包数
    received = int(host.packets_received)  # 收到的回复数
    if received > 0 and host.is_alive:  # 至少一包有回复
        return True, "可以 Ping 通（收到 {} 次回复，发送 {} 个，平均 {:.1f} ms）".format(received, sent, float(host.avg_rtt))  # 通
    return False, "无法 Ping 通（发送 {} 个，收到 {} 次回复）".format(sent, received)  # 不通


async def ping_address(ip):  # 向一台服务器发送 4 个 ICMP 包
    if not is_ipv4(ip):  # 再次拒绝非法地址
        raise ValueError("IP 无效")  # 不发包
    return await async_ping(ip, count=PING_COUNT, interval=PING_INTERVAL, timeout=PING_TIMEOUT, privileged=True)  # icmplib 原始套接字


def lamp_color(state):  # 把状态转成灯的颜色
    if state == LAMP_UP:  # Ping 通
        return GREEN  # 绿色
    if state == LAMP_DOWN:  # 未 Ping 通
        return RED  # 红色
    return GRAY  # 尚未出结果


async def ping_many(ips, stop_event, on_log, on_result):  # 批量并发探测，每台 4 个包
    semaphore = asyncio.Semaphore(PING_CONCURRENCY)  # 限制同时进行的地址数
    ok_count = 0  # 通的数量
    bad_count = 0  # 不通或失败的数量
    count_lock = asyncio.Lock()  # 汇总数字只在一处修改

    async def one(index, ip):  # 探测列表中的一台
        nonlocal ok_count, bad_count  # 修改外层汇总
        if stop_event.is_set():  # 已经停止
            return  # 不再领取新地址
        async with semaphore:  # 取得一个并发名额
            if stop_event.is_set():  # 等待名额时被停止
                return  # 离开
            on_log("---- {}/{} {} ----".format(index, len(ips), ip))  # 进度
            try:  # 单台失败不影响其他地址
                host = await ping_address(ip)  # 发送 4 个包
            except (SocketPermissionError, ICMPSocketError, OSError) as exc:  # 套接字或权限
                on_log("失败 {}：{}".format(ip, exc))  # 写入原因
                on_result(ip, False, "未能执行 Ping")  # 右侧红灯并写明没有发出
                async with count_lock:  # 计入失败
                    bad_count += 1  # 加一
                if isinstance(exc, SocketPermissionError):  # 没有 ICMP 权限
                    stop_event.set()  # 停止后续地址
                    on_log("ICMP 套接字没有权限。请用管理员身份重新打开本程序。")  # 说明原因
                return  # 这一台结束
            reached, summary = describe_ping(host)  # 整理回复次数和平均时间
            on_log("结果 {}：{}".format(ip, summary))  # 写入这一台
            on_result(ip, reached, summary)  # 通知右侧点灯
            async with count_lock:  # 更新汇总
                if reached:  # 收到回复
                    ok_count += 1  # 通
                else:  # 没有回复
                    bad_count += 1  # 不通

    tasks = [asyncio.create_task(one(index, ip)) for index, ip in enumerate(ips, 1)]  # 每台一个任务
    try:  # 等待全部任务，停止时允许取消
        await asyncio.gather(*tasks)  # 并发执行
    except asyncio.CancelledError:  # 窗口关闭时任务被取消
        on_log("已停止。")  # 记录
    if stop_event.is_set():  # 用户点了停止或权限不足
        on_log("已停止。")  # 记录
    on_log("汇总：可以 Ping 通 {} 个，无法 Ping 通 {} 个。".format(ok_count, bad_count))  # 本轮汇总
    return ok_count, bad_count  # 交给调用方


def system_exe(name):  # 从系统目录取程序，只给旧结果窗口使用
    root = os.environ.get("SystemRoot", r"C:\Windows")  # 系统根目录
    path = os.path.join(root, "System32", name)  # System32 下的文件
    if os.path.isfile(path):  # 文件存在
        return path  # 返回完整路径
    return name  # 留给后续启动报错


def find_system_ping():  # 查找系统 ping.exe，新界面不调用它
    system_root = os.environ.get("SystemRoot", r"C:\Windows")  # 系统根目录
    candidates = [  # 可能的位置
        os.path.join(system_root, "System32", "ping.exe"),  # 常规路径
        os.path.join(system_root, "Sysnative", "ping.exe"),  # 32 位进程看到的 64 位目录
        os.path.join(system_root, "SysWOW64", "ping.exe"),  # 32 位系统目录
    ]  # 候选结束
    for path in candidates:  # 逐个查看
        if os.path.isfile(path) and os.path.basename(path).lower() == "ping.exe":  # 文件名必须是 ping.exe
            return path  # 找到
    found = shutil.which("ping")  # 再看 PATH
    if found and os.path.basename(found).lower() == "ping.exe" and os.path.isfile(found):  # PATH 里也必须叫这个名字
        return os.path.abspath(found)  # 绝对路径
    return ""  # 没有找到


def validated_command(cmd):  # 拒绝空参数和换行
    clean = []  # 通过的参数
    for part in cmd:  # 逐个查看
        if not isinstance(part, str) or part == "":  # 空参数
            raise ValueError("参数为空")  # 阻止
        if "\x00" in part or "\r" in part or "\n" in part:  # 换行或空字符
            raise ValueError("参数含有换行")  # 阻止
        clean.append(part)  # 保留
    return clean  # 返回数组


def build_ping_cmd(ping_exe, ip, count, wait_ms):  # 旧结果窗口仍用系统 ping.exe 时的参数
    if not isinstance(ping_exe, str) or os.path.basename(ping_exe).lower() != "ping.exe":  # 只允许这个文件名
        raise ValueError("ping.exe 无效")  # 阻止
    if not os.path.isfile(ping_exe):  # 路径要存在
        raise ValueError("未找到系统 ping.exe")  # 阻止
    if not is_ipv4(ip):  # 地址再检查一次
        raise ValueError("IP 无效")  # 阻止
    if not isinstance(count, int) or count < 1 or count > 4:  # 次数限制
        raise ValueError("Ping 次数无效")  # 阻止
    if not isinstance(wait_ms, int) or wait_ms < 100 or wait_ms > 2000:  # 超时限制
        raise ValueError("Ping 超时无效")  # 阻止
    return validated_command([os.path.abspath(ping_exe), "-n", str(count), "-w", str(wait_ms), ip])  # 参数数组


def format_cmd(cmd):  # 把参数显示成一行
    shown = []  # 显示片段
    for part in cmd:  # 逐个参数
        if any(ch in part for ch in (" ", "\t", '"')):  # 含空白时加引号
            shown.append('"' + part.replace('"', '\\"') + '"')  # 转义
        else:  # 普通参数
            shown.append(part)  # 原样
    return " ".join(shown)  # 拼成一行


def hidden_startupinfo():  # 隐藏子进程窗口
    info = subprocess.STARTUPINFO()  # 启动信息
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # 使用显示标志
    info.wShowWindow = 0  # 不显示
    return info  # 交给 Popen


def spawn(cmd):  # 旧结果窗口启动 ping.exe 的入口
    clean = validated_command(cmd)  # 再检查参数
    return subprocess.Popen(clean, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, startupinfo=hidden_startupinfo())  # 不经过 cmd.exe


def kill_process(proc):  # 结束旧结果窗口拉起的子进程
    if proc is None:  # 没有进程
        return  # 返回
    pid = getattr(proc, "pid", None)  # 进程号
    if not isinstance(pid, int) or pid <= 0:  # 无效进程号
        return  # 不调用
    if proc.poll() is not None:  # 已经结束
        return  # 返回
    taskkill = system_exe("taskkill.exe")  # 系统 taskkill
    try:  # 结束进程树
        subprocess.call([taskkill, "/F", "/T", "/PID", str(pid)], startupinfo=hidden_startupinfo(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # 只结束这个 PID
    except OSError:  # taskkill 没有启动
        pass  # 改用进程对象
    if proc.poll() is None:  # 仍在运行
        try:  # 再结束一次
            proc.kill()  # 结束
        except OSError:  # 刚好退出
            pass  # 忽略


def decode_output(data):  # 解码子进程输出
    if not data:  # 空输出
        return ""  # 空文字
    try:  # 优先 UTF-8
        return data.decode("utf-8")  # 成功就用
    except UnicodeDecodeError:  # 中文 Windows 可能是 ANSI
        pass  # 试下一种
    try:  # 系统 ANSI
        return data.decode("mbcs")  # 解码
    except (LookupError, UnicodeDecodeError):  # 仍失败
        return data.decode("latin1", "replace")  # 保证能显示


def read_process_lines(proc, on_line, stop_event):  # 旧结果窗口读取 ping.exe 输出
    pending = b""  # 未完成的一行
    stream = proc.stdout  # 标准输出
    if stream is None:  # 没有管道
        return  # 无法读
    while True:  # 一直读到结束或停止
        if stop_event is not None and stop_event.is_set():  # 用户停止
            kill_process(proc)  # 结束进程
            break  # 离开
        try:  # 读取可能失败
            chunk = stream.read(256)  # 一小段
        except OSError:  # 管道关闭
            break  # 离开
        if not chunk:  # 没有更多输出
            break  # 离开
        pending += chunk  # 接到缓冲
        while True:  # 交出完整行
            split_at = pending.find(b"\n")  # 换行位置
            if split_at < 0:  # 还没凑成一行
                break  # 再读
            raw = pending[:split_at]  # 这一行
            pending = pending[split_at + 1:]  # 剩下的字节
            on_line(decode_output(raw).rstrip("\r"))  # 交给调用方
    if pending:  # 最后一行没有换行
        on_line(decode_output(pending).rstrip("\r"))  # 仍然交出


def ping_conclusion(text):  # 旧结果窗口按 TTL 判断
    count = len(re.findall(r"TTL\s*=", text, re.IGNORECASE))  # 回复次数
    if count > 0:  # 有回复
        return True, "可以 Ping 通（收到 {} 次回复）".format(count)  # 通
    return False, "无法 Ping 通"  # 不通


def read_text_file(path):  # 读取列表，兼容 UTF-8 和 UTF-16
    handle = open(path, "rb")  # 按字节读
    try:  # 保证关闭
        data = handle.read()  # 全部内容
    finally:  # 关闭文件
        handle.close()  # 释放
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):  # UTF-16
        return data.decode("utf-16")  # 解码
    if data.startswith(b"\xef\xbb\xbf"):  # UTF-8 BOM
        return data.decode("utf-8-sig")  # 去掉 BOM
    try:  # 普通 UTF-8
        return data.decode("utf-8")  # 解码
    except UnicodeDecodeError:  # ANSI
        return data.decode("mbcs", "replace")  # 系统代码页


def choose_font(root, candidates):  # 选择已安装字体
    try:  # 枚举可能失败
        names = list(tkfont.families(root))  # 字体名
    except tk.TclError:  # 枚举失败
        names = []  # 用默认
    lookup = {}  # 小写查找
    for name in names:  # 填表
        lookup[name.lower()] = name  # 保留原名
    for candidate in candidates:  # 按偏好
        found = lookup.get(candidate.lower())  # 查找
        if found:  # 存在
            return found  # 使用
    return "TkDefaultFont"  # 默认字体


def write_error_log(text):  # 写入未捕获异常
    try:  # 写失败时静默
        path = os.path.join(app_base_dir(), "SaoMiao_Ping_error.log")  # 日志路径
        handle = open(path, "ab")  # 追加
        try:  # 保证关闭
            payload = "\r\n[{}]\r\n{}\r\n".format(time.strftime("%Y-%m-%d %H:%M:%S"), text)  # 时间和堆栈
            handle.write(payload.encode("utf-8", "replace"))  # UTF-8
        finally:  # 关闭
            handle.close()  # 释放
    except OSError:  # 不能写
        pass  # 忽略


class App(object):  # Ping 窗口
    def __init__(self, root):  # 建立界面
        self.root = root  # 主窗口
        self.root.title("SaoMiao_Ping 并发探测")  # 标题
        self.root.configure(bg=WHITE)  # 白底
        self.root.option_add("*Background", WHITE)  # 默认白底
        self.root.option_add("*Foreground", BLACK)  # 默认黑字
        self.root.option_add("*selectBackground", BLACK)  # 选中黑底
        self.root.option_add("*selectForeground", WHITE)  # 选中白字
        family = choose_font(root, ("Microsoft YaHei UI", "Microsoft YaHei", "SimSun", "Tahoma", "Arial"))  # 中文字体
        mono = choose_font(root, ("Consolas", "Courier New", "SimSun"))  # 等宽字体
        self.font_title = (family, 20, "bold")  # 标题
        self.font_body = (family, 10)  # 正文
        self.font_small = (family, 9)  # 小字
        self.font_mono = (mono, 10)  # 日志和多行地址
        self.queue = queue.Queue()  # 日志队列
        self.stop_event = threading.Event()  # 停止标记
        self.scanning = False  # 是否正在探测
        self.alive = True  # 窗口是否还在
        self.log_lines = []  # 报告日志
        self.ips = []  # 服务器列表
        self.ip_set = set()  # 去重
        self.ip_var = tk.StringVar()  # 单个地址
        self.start_var = tk.StringVar()  # 网段起点
        self.end_var = tk.StringVar()  # 网段终点
        self.count_var = tk.StringVar()  # 数量
        self.status_var = tk.StringVar()  # 状态栏
        self.summary_var = tk.StringVar()  # 右侧通与不通的数量
        self.all_var = tk.StringVar()  # 右侧全部地址标题
        self.focus_ip_var = tk.StringVar()  # 右侧大灯上的地址
        self.focus_state_var = tk.StringVar()  # 右侧大灯上的汉字结论
        self.focus_data_var = tk.StringVar()  # 右侧大灯上的回复说明
        self.cards = {}  # 最近一张同地址卡片
        self.card_rows = []  # 按输入顺序保存每一行灯
        self.order = []  # 右侧地址顺序
        self.ping_up = 0  # 绿灯数量
        self.ping_down = 0  # 红灯数量
        self.focus_ip_var.set("尚未选择")  # 还没有探测
        self.focus_state_var.set("等待 Ping")  # 初始汉字
        self.focus_data_var.set("")  # 还没有回复数据
        self.summary_var.set("Ping通 0    未Ping通 0")  # 初始数量
        self.all_var.set("全部地址")  # 初始标题
        self.build_ui()  # 画界面
        self.rebuild_multi_menu()  # 初始菜单
        self.refresh_count()  # 数量为 0
        self.refresh_run_buttons()  # 停止按钮空闲
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)  # 关闭时停止
        self.root.after(80, self.pump)  # 开始取日志
        self.append_log("SaoMiao_Ping {} 已启动。只测试你有权测试的服务器。".format(VERSION))  # 开场
        self.append_log("每台发送 {} 个 ICMP 包，同时最多 {} 台。不调用 ping.exe。".format(PING_COUNT, PING_CONCURRENCY))  # 说明发包方式
        self.append_log("第一行可填一个 IP，或多个 IP 用英文逗号分开。右侧用绿灯和红灯显示结果。")  # 说明第一行和右侧

    def build_ui(self):  # 排列控件
        screen_h = self.root.winfo_screenheight()  # 屏幕高度
        height = 980 if screen_h >= 1040 else 760  # 给多行地址和日志留高度
        self.root.geometry("1280x{}".format(height))  # 加宽后把红绿灯放在最右边
        self.root.minsize(1100, 640)  # 最小大小
        self.build_result_panel()  # 最右边先放结果栏，避免被左侧挤掉
        header = tk.Frame(self.root, bg=BLACK, bd=0, highlightthickness=0)  # 黑标题
        header.pack(fill="x")  # 铺满
        tk.Label(header, text="PING", bg=BLACK, fg=WHITE, font=self.font_title, anchor="w").pack(fill="x", padx=16, pady=(12, 0))  # 标题
        tk.Label(header, text="并发 ICMP    每台 4 个包", bg=BLACK, fg=WHITE, font=self.font_body, anchor="w").pack(fill="x", padx=16)  # 副标题
        actions = tk.Frame(header, bg=BLACK, bd=0, highlightthickness=0)  # 报告按钮
        actions.pack(fill="x", padx=16, pady=(8, 12))  # 位置
        self.make_button(actions, "日志报告", self.save_report, primary=True).pack(side="right")  # 保存
        self.make_button(actions, "打开报告目录", self.open_report_dir).pack(side="right", padx=(0, 6))  # 目录
        self.make_button(actions, "清空日志", self.clear_log).pack(side="right", padx=(0, 6))  # 清空
        form = tk.Frame(self.root, bg=WHITE, bd=0, highlightthickness=0)  # 左侧表单
        form.pack(fill="x", padx=16, pady=(12, 0))  # 边距
        tk.Label(form, text="单个或多个 IP", bg=WHITE, fg=BLACK, font=self.font_body, anchor="w").pack(fill="x")  # 第一行标题
        tk.Label(form, text="一个地址直接填写。多个地址用英文逗号分开，例如 192.168.1.10,192.168.1.11", bg=WHITE, fg=BLACK, font=self.font_small, anchor="w").pack(fill="x")  # 逗号说明
        single_row = tk.Frame(form, bg=WHITE, bd=0, highlightthickness=0)  # 单地址行
        single_row.pack(fill="x", pady=(4, 8))  # 间距
        single_row.grid_columnconfigure(0, weight=1)  # 输入框拉伸
        single_shell, single_inner = self.boxed(single_row)  # 黑边
        single_shell.grid(row=0, column=0, sticky="ew")  # 放置
        self.single_entry = tk.Entry(single_inner, textvariable=self.ip_var, bg=WHITE, fg=BLACK, insertbackground=BLACK, relief="flat", bd=0, highlightthickness=0, font=self.font_body)  # 单个地址
        self.single_entry.pack(fill="x", padx=8, pady=6)  # 内边距
        self.single_entry.bind("<Return>", self.on_single_return)  # 回车探测
        self.make_button(single_row, "测试 Ping", self.ping_single, primary=True).grid(row=0, column=1, padx=(8, 0))  # 一个或多个地址都从这里测试
        tk.Label(form, text="多行地址（每行一个 IP，可直接粘贴）", bg=WHITE, fg=BLACK, font=self.font_body, anchor="w").pack(fill="x")  # 大输入框标题
        bulk_shell, bulk_inner = self.boxed(form)  # 大输入框边框
        bulk_shell.pack(fill="x", pady=(4, 4))  # 间距
        bulk_inner.grid_columnconfigure(0, weight=1)  # 文本拉伸
        bulk_inner.grid_rowconfigure(0, weight=1)  # 高度固定由控件决定
        self.bulk_text = tk.Text(bulk_inner, height=8, bg=WHITE, fg=BLACK, insertbackground=BLACK, relief="flat", bd=0, highlightthickness=0, font=self.font_mono, wrap="none", undo=True)  # 竖着粘贴多个地址
        bulk_y = self.make_scrollbar(bulk_inner, "vertical", self.bulk_text.yview)  # 大框滚动条
        self.bulk_text.configure(yscrollcommand=bulk_y.set)  # 关联
        self.bulk_text.grid(row=0, column=0, sticky="nsew")  # 放在左边
        bulk_y.grid(row=0, column=1, sticky="ns")  # 滚动条在框内右侧
        bulk_buttons = tk.Frame(form, bg=WHITE, bd=0, highlightthickness=0)  # 大框按钮
        bulk_buttons.pack(fill="x", pady=(0, 8))  # 间距
        self.make_button(bulk_buttons, "Ping 框内地址", self.ping_bulk, primary=True).pack(side="left")  # 直接并发探测
        self.make_button(bulk_buttons, "加入列表", self.add_from_bulk).pack(side="left", padx=(6, 0))  # 先放进列表
        multi_row = tk.Frame(form, bg=WHITE, bd=0, highlightthickness=0)  # 列表操作
        multi_row.pack(fill="x", pady=(0, 6))  # 间距
        self.multi_button = tk.Menubutton(multi_row, text="多IP服务器", font=self.font_body, bg=BLACK, fg=WHITE, activebackground=WHITE, activeforeground=BLACK, relief="flat", bd=0, highlightthickness=1, highlightbackground=BLACK, padx=12, pady=5, direction="below", cursor="hand2")  # 下拉菜单
        self.multi_menu = tk.Menu(self.multi_button, tearoff=0, bg=WHITE, fg=BLACK, activebackground=BLACK, activeforeground=WHITE, font=self.font_body)  # 菜单
        self.multi_button.configure(menu=self.multi_menu)  # 挂上菜单
        self.multi_button.pack(side="left")  # 靠左
        self.make_button(multi_row, "添加", self.add_from_entry, primary=True).pack(side="left", padx=(8, 0))  # 从单行加入
        self.make_button(multi_row, "导入 IP_LieBiao.txt", self.import_list).pack(side="left", padx=(6, 0))  # 导入文件
        self.make_button(multi_row, "删除选中", self.remove_selected).pack(side="left", padx=(6, 0))  # 删除
        self.make_button(multi_row, "清空列表", self.clear_list).pack(side="left", padx=(6, 0))  # 清空
        list_head = tk.Frame(form, bg=WHITE, bd=0, highlightthickness=0)  # 列表标题
        list_head.pack(fill="x")  # 铺满
        tk.Label(list_head, text="多 IP 服务器列表", bg=WHITE, fg=BLACK, font=self.font_body).pack(side="left")  # 名称
        tk.Label(list_head, textvariable=self.count_var, bg=WHITE, fg=BLACK, font=self.font_small).pack(side="right")  # 数量
        list_shell, list_inner = self.boxed(form)  # 列表边框
        list_shell.pack(fill="x", pady=(4, 8))  # 间距
        list_inner.grid_columnconfigure(0, weight=1)  # 列表拉伸
        self.listbox = tk.Listbox(list_inner, height=4, bg=WHITE, fg=BLACK, selectbackground=BLACK, selectforeground=WHITE, selectmode="extended", activestyle="none", relief="flat", bd=0, highlightthickness=0, font=self.font_body, exportselection=False)  # 地址列表
        list_y = self.make_scrollbar(list_inner, "vertical", self.listbox.yview)  # 列表滚动条
        self.listbox.configure(yscrollcommand=list_y.set)  # 关联
        self.listbox.grid(row=0, column=0, sticky="nsew")  # 放置
        list_y.grid(row=0, column=1, sticky="ns")  # 滚动条
        tk.Label(form, text="IP 连续网段", bg=WHITE, fg=BLACK, font=self.font_body, anchor="w").pack(fill="x")  # 网段标题
        range_row = tk.Frame(form, bg=WHITE, bd=0, highlightthickness=0)  # 起止和菜单
        range_row.pack(fill="x", pady=(4, 4))  # 间距
        tk.Label(range_row, text="起始IP", bg=WHITE, fg=BLACK, font=self.font_body).pack(side="left")  # 起点标签
        start_shell, start_inner = self.boxed(range_row)  # 起点边框
        start_shell.pack(side="left", padx=(6, 8))  # 位置
        tk.Entry(start_inner, textvariable=self.start_var, width=16, bg=WHITE, fg=BLACK, insertbackground=BLACK, relief="flat", bd=0, highlightthickness=0, font=self.font_body).pack(padx=8, pady=6)  # 起点输入
        tk.Label(range_row, text="结束IP", bg=WHITE, fg=BLACK, font=self.font_body).pack(side="left")  # 终点标签
        end_shell, end_inner = self.boxed(range_row)  # 终点边框
        end_shell.pack(side="left", padx=(6, 8))  # 位置
        tk.Entry(end_inner, textvariable=self.end_var, width=16, bg=WHITE, fg=BLACK, insertbackground=BLACK, relief="flat", bd=0, highlightthickness=0, font=self.font_body).pack(padx=8, pady=6)  # 终点输入
        self.range_button = tk.Menubutton(range_row, text="IP连续网段", font=self.font_body, bg=BLACK, fg=WHITE, activebackground=WHITE, activeforeground=BLACK, relief="flat", bd=0, highlightthickness=1, highlightbackground=BLACK, padx=12, pady=5, direction="below", cursor="hand2")  # 网段菜单按钮
        self.range_menu = tk.Menu(self.range_button, tearoff=0, bg=WHITE, fg=BLACK, activebackground=BLACK, activeforeground=WHITE, font=self.font_body)  # 网段菜单
        self.range_button.configure(menu=self.range_menu)  # 挂上
        self.fill_range_menu()  # 写入项目
        self.range_button.pack(side="left")  # 放在右侧
        tk.Label(form, text="同网段项目只使用起始IP的前三段。每台都发 4 个包，一次最多 {} 个地址。".format(MAX_RANGE), bg=WHITE, fg=BLACK, font=self.font_small, anchor="w").pack(fill="x", pady=(0, 8))  # 说明
        run_row = tk.Frame(form, bg=WHITE, bd=0, highlightthickness=0)  # 停止行
        run_row.pack(fill="x", pady=(0, 8))  # 间距
        self.stop_button = self.make_button(run_row, "停止", self.stop_ping)  # 停止
        self.stop_button.pack(side="left")  # 靠左
        log_shell, log_inner = self.boxed(self.root)  # 日志边框
        log_shell.pack(fill="both", expand=True, padx=16, pady=(0, 8))  # 占据剩余高度
        log_inner.grid_rowconfigure(0, weight=1)  # 纵向拉伸
        log_inner.grid_columnconfigure(0, weight=1)  # 横向拉伸
        self.log_text = tk.Text(log_inner, bg=WHITE, fg=BLACK, insertbackground=BLACK, relief="flat", bd=0, highlightthickness=0, font=self.font_mono, wrap="word")  # 日志
        log_y = self.make_scrollbar(log_inner, "vertical", self.log_text.yview)  # 日志滚动条
        self.log_text.configure(yscrollcommand=log_y.set)  # 关联
        self.log_text.grid(row=0, column=0, sticky="nsew")  # 放置
        log_y.grid(row=0, column=1, sticky="ns")  # 滚动条
        self.log_text.bind("<Key>", self.on_log_key)  # 只允许复制
        tk.Label(self.root, textvariable=self.status_var, bg=BLACK, fg=WHITE, font=self.font_small, anchor="w").pack(fill="x")  # 状态栏
        self.status_var.set("  SaoMiao_Ping v{}    右侧显示 Ping 红绿灯    每台 {} 个包".format(VERSION, PING_COUNT))  # 状态文字

    def build_result_panel(self):  # 最右边的红绿灯，版式与以前的结果栏一致
        self.result_panel = tk.Frame(self.root, bg=WHITE, width=440, bd=0, highlightthickness=0)  # 右侧结果栏
        self.result_panel.pack(side="right", fill="y")  # 贴在窗口最右
        self.result_panel.pack_propagate(False)  # 宽度固定，高度跟随窗口
        cap = tk.Frame(self.result_panel, bg=BLACK, bd=0, highlightthickness=0)  # 黑色标题
        cap.pack(fill="x")  # 铺满顶部
        tk.Label(cap, text="结果", bg=BLACK, fg=WHITE, font=self.font_title, anchor="w").pack(fill="x", padx=12, pady=(12, 0))  # 右侧标题
        tk.Label(cap, textvariable=self.summary_var, bg=BLACK, fg=WHITE, font=self.font_body, anchor="w").pack(fill="x", padx=12, pady=(0, 12))  # 通与不通的数量
        focus = tk.Frame(self.result_panel, bg=WHITE, bd=0, highlightthickness=0)  # 最近一台的大灯
        focus.pack(fill="x", padx=12, pady=(12, 8))  # 放在列表上方
        self.focus_lamp = tk.Canvas(focus, width=56, height=56, bg=WHITE, highlightthickness=0, bd=0)  # 大灯画布
        self.focus_lamp.pack(side="left")  # 灯在左
        self.focus_oval = self.focus_lamp.create_oval(6, 6, 50, 50, fill=GRAY, outline=GRAY)  # 先画灰灯
        focus_text = tk.Frame(focus, bg=WHITE, bd=0, highlightthickness=0)  # 大灯右侧文字
        focus_text.pack(side="left", fill="x", expand=True, padx=(8, 0))  # 紧挨着灯
        tk.Label(focus_text, textvariable=self.focus_ip_var, bg=WHITE, fg=BLACK, font=self.font_body, anchor="w").pack(fill="x")  # 当前地址
        self.focus_state_label = tk.Label(focus_text, textvariable=self.focus_state_var, bg=WHITE, fg=GRAY, font=self.font_body, anchor="w")  # Ping通或未Ping通
        self.focus_state_label.pack(fill="x")  # 汉字结论
        tk.Label(focus_text, textvariable=self.focus_data_var, bg=WHITE, fg=BLACK, font=self.font_small, anchor="w", justify="left", wraplength=300).pack(fill="x")  # 回复次数说明
        tk.Label(self.result_panel, textvariable=self.all_var, bg=WHITE, fg=BLACK, font=self.font_body, anchor="w").pack(fill="x", padx=12)  # 列表标题
        list_shell = tk.Frame(self.result_panel, bg=BLACK, bd=0, highlightthickness=0, padx=1, pady=1)  # 列表黑边
        list_shell.pack(fill="both", expand=True, padx=12, pady=(4, 12))  # 占据右侧剩余高度
        self.result_canvas = tk.Canvas(list_shell, bg=WHITE, highlightthickness=0, bd=0)  # 可滚动结果区
        self.result_canvas.pack(side="left", fill="both", expand=True)  # 放在滚动条左边
        self.result_scroll = self.make_scrollbar(list_shell, "vertical", self.result_canvas.yview)  # 可拖动的滚动条
        self.result_scroll.configure(width=18)  # 加粗，方便按住下拉
        self.result_scroll.pack(side="right", fill="y")  # 贴在结果栏最右
        self.result_canvas.configure(yscrollcommand=self.result_scroll.set)  # 关联滚动
        self.result_inner = tk.Frame(self.result_canvas, bg=WHITE, bd=0, highlightthickness=0)  # 卡片容器
        self.result_window = self.result_canvas.create_window((0, 0), window=self.result_inner, anchor="nw")  # 放入画布
        self.result_inner.bind("<Configure>", lambda _event: self.refresh_result_scroll())  # 内容变高后更新滚动范围
        self.result_canvas.bind("<Configure>", self.on_result_canvas_configure)  # 宽度跟着结果栏变化
        self.root.bind_all("<MouseWheel>", self.on_result_wheel)  # 鼠标在右侧时用滚轮下拉

    def on_result_canvas_configure(self, event):  # 结果栏变宽时卡片跟着变宽
        self.result_canvas.itemconfigure(self.result_window, width=event.width)  # 只改宽度
        self.show_result_top()  # 重新计算可滚动范围

    def pointer_in_result(self, widget):  # 判断鼠标是否停在右侧结果栏
        current = widget  # 从事件控件开始
        while current is not None:  # 一直找到顶层窗口
            if current == self.result_panel:  # 属于右侧结果栏
                return True  # 滚轮交给结果列表
            current = getattr(current, "master", None)  # 看上一层
        return False  # 鼠标在左侧

    def on_result_wheel(self, event):  # 鼠标滚轮下拉右侧全部地址
        if not self.pointer_in_result(event.widget):  # 指针不在右侧
            return None  # 留给左侧日志自己滚动
        steps = int(-event.delta / 120)  # Windows 一格通常是 120
        if steps == 0:  # 高精度鼠标的小幅度滚动
            steps = -1 if event.delta > 0 else 1  # 仍按方向移动一格
        self.result_canvas.yview_scroll(steps, "units")  # 移动结果列表
        return "break"  # 不再把滚轮传给别的控件

    def refresh_result_scroll(self):  # 按实际内容高度打开滚动
        try:  # 窗口关闭时画布可能已销毁
            self.result_inner.update_idletasks()  # 先算出卡片高度
            height = self.result_inner.winfo_reqheight()  # 全部地址的高度
            width = self.result_canvas.winfo_width()  # 当前可视宽度
            if width < 2:  # 窗口还没完成布局
                width = 400  # 用结果栏的大致宽度
            self.result_canvas.itemconfigure(self.result_window, width=width, height=height)  # 内容保持完整高度
            self.result_canvas.configure(scrollregion=(0, 0, width, height))  # 滚动范围覆盖到最后一台
        except tk.TclError:  # 控件已经不存在
            self.alive = False  # 停止后续刷新

    def show_result_top(self):  # 新一轮从列表顶部开始
        self.refresh_result_scroll()  # 先算出完整高度
        try:  # 再回到第一台
            self.result_canvas.yview_moveto(0)  # 后面的地址跟着出现
        except tk.TclError:  # 控件已经不存在
            self.alive = False  # 停止后续刷新

    def paint_lamp(self, canvas, oval, state):  # 给指定圆灯填色
        color = lamp_color(state)  # 取出红、绿或灰
        canvas.itemconfigure(oval, fill=color, outline=color)  # 填充这盏灯

    def set_focus(self, ip, state, state_text, data_text):  # 更新右上角大灯
        self.focus_ip_var.set(ip or "尚未选择")  # 显示地址
        self.focus_state_var.set(state_text)  # 显示 Ping通或未Ping通
        self.focus_data_var.set(data_text)  # 显示回复次数
        self.focus_state_label.configure(fg=lamp_color(state))  # 汉字和灯同色
        self.paint_lamp(self.focus_lamp, self.focus_oval, state)  # 点亮大灯

    def refresh_summary(self):  # 更新右侧顶部数量
        self.summary_var.set("Ping通 {}    未Ping通 {}".format(self.ping_up, self.ping_down))  # 两个数字都显示

    def clear_cards(self):  # 清空右侧地址卡片
        for child in list(self.result_inner.winfo_children()):  # 逐个移除
            child.destroy()  # 销毁旧卡片
        self.cards = {}  # 清空索引
        self.card_rows = []  # 清空每一行
        self.order = []  # 清空顺序
        self.ping_up = 0  # 绿灯归零
        self.ping_down = 0  # 红灯归零
        self.all_var.set("全部地址")  # 标题回到空列表
        self.refresh_summary()  # 刷新顶部数字
        self.set_focus("", LAMP_WAIT, "等待 Ping", "")  # 大灯回到等待
        self.show_result_top()  # 回到顶部

    def add_card(self, ip):  # 为这个 IP 增加一行灯
        row = tk.Frame(self.result_inner, bg=WHITE, bd=0, highlightthickness=0)  # 一行结果
        row.pack(fill="x", padx=8, pady=(8, 0))  # 上下留白
        lamp = tk.Canvas(row, width=28, height=28, bg=WHITE, highlightthickness=0, bd=0)  # 小灯画布
        lamp.grid(row=0, column=0, rowspan=3, sticky="n", padx=(0, 8))  # 灯占左侧
        oval = lamp.create_oval(4, 4, 24, 24, fill=GRAY, outline=GRAY)  # 先画灰灯
        tk.Label(row, text=ip, bg=WHITE, fg=BLACK, font=self.font_body, anchor="w").grid(row=0, column=1, sticky="ew")  # 地址
        state_label = tk.Label(row, text="等待 Ping", bg=WHITE, fg=GRAY, font=self.font_body, anchor="w")  # 初始汉字
        state_label.grid(row=1, column=1, sticky="ew")  # 第二行
        data_label = tk.Label(row, text="", bg=WHITE, fg=BLACK, font=self.font_small, anchor="w", justify="left", wraplength=320)  # 回复说明
        data_label.grid(row=2, column=1, sticky="ew")  # 第三行
        tk.Frame(self.result_inner, bg=BLACK, height=1, bd=0, highlightthickness=0).pack(fill="x", padx=8, pady=(8, 0))  # 分隔线
        row.grid_columnconfigure(1, weight=1)  # 文字列拉伸
        card = {"ip": ip, "done": False, "lamp": lamp, "oval": oval, "state": state_label, "data": data_label}  # 这一行的灯和文字
        self.card_rows.append(card)  # 按输入顺序追加
        self.cards[ip] = card  # 同地址时指向最新一行
        self.order.append(ip)  # 记住顺序

    def prepare_cards(self, hosts):  # 探测前先摆出灰灯
        self.clear_cards()  # 清掉上一轮
        for ip in hosts:  # 每个地址一行
            self.add_card(ip)  # 创建灰灯
        self.all_var.set("全部地址  {} 个".format(len(hosts)))  # 标题写出数量
        self.show_result_top()  # 从第一台开始显示
        if len(hosts) == 1:  # 只有一台
            self.set_focus(hosts[0], LAMP_WAIT, "等待 Ping", "正在检测这一台服务器")  # 大灯等待
        elif hosts:  # 多台
            self.set_focus(hosts[0], LAMP_WAIT, "等待 Ping", "共 {} 个地址，每台都会单独亮灯".format(len(hosts)))  # 说明数量

    def apply_ping(self, ip, reached, summary):  # 把一台服务器的结果点到灯上
        card = None  # 先找还没点亮的那一行
        for item in self.card_rows:  # 按输入顺序查找
            if item["ip"] == ip and not item["done"]:  # 同一地址的下一行
                card = item  # 用这一行
                break  # 找到就停止
        if card is None:  # 没有等待中的行
            card = self.cards.get(ip)  # 用最新一行
        if card is None:  # 卡片已经清掉
            return  # 不再更新
        card["done"] = True  # 这一行已经有结果
        state = LAMP_UP if reached else LAMP_DOWN  # 通为绿，不通为红
        word = "Ping通" if reached else "未Ping通"  # 汉字结论
        self.paint_lamp(card["lamp"], card["oval"], state)  # 点亮这一行的圆灯
        card["state"].configure(text=word, fg=lamp_color(state))  # 用相同颜色写汉字
        card["data"].configure(text=summary)  # 写入回复次数或无法 Ping 通
        if reached:  # 这台通了
            self.ping_up += 1  # 增加绿灯数量
        else:  # 这台没通
            self.ping_down += 1  # 增加红灯数量
        self.refresh_summary()  # 刷新右侧顶部
        self.set_focus(ip, state, word, summary)  # 大灯显示最近这一台

    def boxed(self, parent):  # 一像素黑边
        shell = tk.Frame(parent, bg=BLACK, bd=0, highlightthickness=0, padx=1, pady=1)  # 外层
        inner = tk.Frame(shell, bg=WHITE, bd=0, highlightthickness=0)  # 内层
        inner.pack(fill="both", expand=True)  # 铺满
        return shell, inner  # 返回

    def make_button(self, parent, text, command, primary=False):  # 黑白按钮
        bg = BLACK if primary else WHITE  # 背景
        fg = WHITE if primary else BLACK  # 文字
        return tk.Button(parent, text=text, command=command, font=self.font_body, bg=bg, fg=fg, activebackground=WHITE if primary else BLACK, activeforeground=BLACK if primary else WHITE, relief="flat", bd=0, highlightthickness=1, highlightbackground=BLACK, highlightcolor=BLACK, padx=12, pady=5, cursor="hand2", takefocus=True)  # 返回按钮

    def make_scrollbar(self, parent, orient, command):  # 黑白滚动条
        return tk.Scrollbar(parent, orient=orient, command=command, bg=BLACK, activebackground=BLACK, troughcolor=WHITE, highlightthickness=0, bd=0, width=12, relief="flat", elementborderwidth=1)  # 返回滚动条

    def paint_button(self, button, text, primary):  # 改变按钮颜色
        bg = BLACK if primary else WHITE  # 背景
        fg = WHITE if primary else BLACK  # 文字
        button.configure(text=text, bg=bg, fg=fg, activebackground=WHITE if primary else BLACK, activeforeground=BLACK if primary else WHITE, highlightbackground=BLACK, highlightcolor=BLACK)  # 应用

    def refresh_run_buttons(self):  # 探测中强调停止
        if self.scanning:  # 正在探测
            self.paint_button(self.stop_button, "停止", True)  # 黑底
        else:  # 空闲
            self.paint_button(self.stop_button, "停止", False)  # 白底

    def on_log_key(self, event):  # 日志只允许复制和全选
        if event.state & 4 and event.keysym.lower() in ("c", "a"):  # Ctrl+C 或 Ctrl+A
            return None  # 放行
        return "break"  # 阻止修改

    def fill_range_menu(self):  # 连续网段菜单
        self.range_menu.add_command(label="按起始IP到结束IP连续 Ping", command=self.ping_custom_range)  # 自定义起止
        self.range_menu.add_command(label="同网段最后一段 1 到 50", command=lambda: self.ping_octet_range(1, 50))  # 第一段
        self.range_menu.add_command(label="同网段最后一段 51 到 100", command=lambda: self.ping_octet_range(51, 100))  # 第二段
        self.range_menu.add_command(label="同网段最后一段 101 到 150", command=lambda: self.ping_octet_range(101, 150))  # 第三段
        self.range_menu.add_command(label="同网段最后一段 151 到 200", command=lambda: self.ping_octet_range(151, 200))  # 第四段
        self.range_menu.add_command(label="同网段最后一段 201 到 254", command=lambda: self.ping_octet_range(201, 254))  # 第五段
        self.range_menu.add_command(label="同网段最后一段 1 到 254", command=lambda: self.ping_octet_range(1, 254))  # 整段

    def rebuild_multi_menu(self):  # 按列表重做下拉菜单
        self.multi_menu.delete(0, "end")  # 清掉旧项
        self.multi_menu.add_command(label="Ping 全部已加入的服务器", command=self.ping_all_added)  # 全部
        self.multi_menu.add_command(label="Ping 列表里选中的服务器", command=self.ping_selected)  # 选中
        self.multi_menu.add_separator()  # 分隔
        if not self.ips:  # 还没有地址
            self.multi_menu.add_command(label="（请先添加或导入 IP）", state="disabled")  # 提示
            return  # 结束
        shown = self.ips[:MAX_MENU_ITEMS]  # 菜单只列前若干条
        for ip in shown:  # 每个地址一项
            self.multi_menu.add_command(label="Ping {}".format(ip), command=lambda target=ip: self.start_ping([target], "多IP菜单"))  # 只测这一台
        if len(self.ips) > len(shown):  # 还有没列出来的
            self.multi_menu.add_command(label="其余地址请使用“Ping 全部已加入的服务器”", state="disabled")  # 说明

    def refresh_count(self):  # 更新数量
        self.count_var.set("{} 个".format(len(self.ips)))  # 显示

    def append_log(self, text):  # 追加日志
        self.log_lines.append(text)  # 进入报告
        if len(self.log_lines) > 8000:  # 限制长度
            self.log_lines = self.log_lines[-8000:]  # 保留最新
        try:  # 控件可能已销毁
            self.log_text.insert("end", text + "\n")  # 显示
            self.log_text.see("end")  # 滚到末尾
        except tk.TclError:  # 窗口关闭
            self.alive = False  # 停止刷新

    def pump(self):  # 主线程取队列
        if not self.alive:  # 已关闭
            return  # 停止
        try:  # 取空会抛异常
            while True:  # 取完当前消息
                item = self.queue.get_nowait()  # 一条消息
                kind = item[0]  # 消息类型
                if kind == "log":  # 日志
                    self.append_log(item[1])  # 显示
                elif kind == "ping":  # 一台探测完成
                    self.apply_ping(item[1], item[2], item[3])  # 点亮右侧圆灯并写汉字
                elif kind == "done":  # 结束
                    self.scanning = False  # 恢复空闲
                    self.refresh_run_buttons()  # 恢复按钮
        except queue.Empty:  # 队列空
            pass  # 等下一次
        if self.alive:  # 窗口还在
            self.root.after(80, self.pump)  # 继续

    def log_from_worker(self, text):  # 后台写日志
        self.queue.put(("log", text))  # 放入队列

    def result_from_worker(self, ip, reached, summary):  # 后台把一台结果送去点灯
        self.queue.put(("ping", ip, reached, summary))  # 主线程更新右侧圆灯

    def ensure_idle(self):  # 已有探测时不再开第二轮
        if self.scanning:  # 正在探测
            self.append_log("当前测试还没结束，可先点停止。")  # 提示
            return False  # 拒绝
        return True  # 可以开始

    def start_ping(self, ips, title):  # 启动一轮并发探测
        if not self.ensure_idle():  # 正在探测
            return  # 不启动
        clean = []  # 本轮地址
        seen = set()  # 本轮去重
        for ip in ips:  # 再过滤一次
            if is_ipv4(ip) and ip not in seen:  # 合法且不重复
                seen.add(ip)  # 记住
                clean.append(ip)  # 加入
        if not clean:  # 没有地址
            messagebox.showwarning("没有地址", "没有可测试的 IPv4 地址。")  # 提示
            return  # 返回
        self.prepare_cards(clean)  # 右侧先为每个地址摆出灰灯
        self.scanning = True  # 标记进行中
        self.stop_event.clear()  # 清除停止
        self.refresh_run_buttons()  # 停止按钮变黑
        worker = threading.Thread(target=self.worker, args=(clean, title))  # 后台运行 asyncio
        worker.daemon = True  # 窗口关闭后允许结束
        worker.start()  # 启动

    def worker(self, ips, title):  # 在线程里跑并发探测
        self.log_from_worker("开始{}，共 {} 个地址。每台 {} 个 ICMP 包，同时最多 {} 台。".format(title, len(ips), PING_COUNT, PING_CONCURRENCY))  # 范围
        try:  # 套接字错误已在单台里处理
            asyncio.run(ping_many(ips, self.stop_event, self.log_from_worker, self.result_from_worker))  # 并发发包并点亮右侧
        except Exception as exc:  # 整轮没有启动
            self.log_from_worker("探测失败：{}".format(exc))  # 记录
        self.queue.put(("done", ""))  # 恢复按钮

    def on_single_return(self, _event):  # 单行回车
        self.ping_single()  # 探测这一台
        return "break"  # 阻止继续传递

    def ping_single(self):  # 测试第一行里的一个或多个地址
        valids, invalids = parse_ip_tokens(self.ip_var.get())  # 英文逗号会切开多个地址
        for token in invalids:  # 无效内容
            self.append_log("已忽略无效内容：{}".format(token))  # 只记日志
        if not valids:  # 没有合法地址
            messagebox.showwarning("没有地址", "请填写 IPv4。多个地址用英文逗号分开。")  # 提示
            return  # 不开始
        self.start_ping(valids, "IP地址")  # 一个或多个都发 4 个包，右侧逐个亮灯

    def bulk_addresses(self):  # 读取多行框
        return parse_ip_lines(self.bulk_text.get("1.0", "end"))  # 每行一个地址

    def ping_bulk(self):  # 直接探测多行框里的地址
        valids, invalids = self.bulk_addresses()  # 解析
        for token in invalids:  # 无效行
            self.append_log("已忽略无效内容：{}".format(token))  # 只记日志
        if not valids:  # 没有地址
            messagebox.showwarning("没有地址", "请在多行框里竖着粘贴 IPv4，每行一个。")  # 提示
            return  # 不开始
        self.start_ping(valids, "多行地址")  # 并发探测

    def add_from_entry(self):  # 单行加入列表
        valids, invalids = parse_ip_tokens(self.ip_var.get())  # 解析
        for token in invalids:  # 无效内容
            self.append_log("已忽略无效内容：{}".format(token))  # 记录
        added = self.add_ips(valids)  # 加入
        self.append_log("已加入 {} 个地址。".format(added))  # 数量
        if added:  # 确实加入了
            self.ip_var.set("")  # 清空单行

    def add_from_bulk(self):  # 多行框加入列表
        valids, invalids = self.bulk_addresses()  # 解析
        for token in invalids:  # 无效内容
            self.append_log("已忽略无效内容：{}".format(token))  # 记录
        added = self.add_ips(valids)  # 加入
        self.append_log("从多行框加入 {} 个地址。".format(added))  # 数量

    def add_ips(self, valids):  # 按上限加入列表
        added = 0  # 新加入数量
        limited = False  # 是否到上限
        for ip in valids:  # 逐个
            if ip in self.ip_set:  # 已有
                continue  # 跳过
            if len(self.ips) >= MAX_IPS:  # 到上限
                limited = True  # 标记
                break  # 停止
            self.ips.append(ip)  # 保存
            self.ip_set.add(ip)  # 去重
            self.listbox.insert("end", ip)  # 显示
            added += 1  # 计数
        if limited:  # 触顶
            self.append_log("列表已达到 {} 个上限。".format(MAX_IPS))  # 提示
        self.rebuild_multi_menu()  # 刷新菜单
        self.refresh_count()  # 刷新数量
        return added  # 返回

    def import_list(self):  # 导入 IP_LieBiao.txt
        default_path = os.path.join(app_base_dir(), "IP_LieBiao.txt")  # 默认位置
        path = default_path if os.path.isfile(default_path) else ""  # 存在就用
        if not path:  # 旁边没有文件
            path = filedialog.askopenfilename(title="选择 IP 列表", filetypes=[("文本", "*.txt"), ("全部", "*.*")])  # 另选
        if not path:  # 取消
            return  # 不改列表
        if os.path.getsize(path) > MAX_LIST_BYTES:  # 过大
            messagebox.showwarning("文件过大", "列表文件超过 2MB。")  # 提示
            return  # 不读
        text = read_text_file(path)  # 读取
        valids, invalids = parse_ip_lines(text)  # 每行解析
        for token in invalids:  # 无效内容
            self.append_log("导入时已忽略：{}".format(token))  # 记录
        added = self.add_ips(valids)  # 加入
        self.append_log("从 {} 加入 {} 个地址。".format(path, added))  # 来源

    def remove_selected(self):  # 删除选中
        selected = list(self.listbox.curselection())  # 下标
        if not selected:  # 没选
            self.append_log("没有选中要删除的地址。")  # 提示
            return  # 返回
        for index in reversed(selected):  # 从后往前删
            ip = self.ips[index]  # 地址
            del self.ips[index]  # 从列表删除
            self.ip_set.discard(ip)  # 从集合删除
            self.listbox.delete(index)  # 从界面删除
        self.rebuild_multi_menu()  # 刷新菜单
        self.refresh_count()  # 刷新数量

    def clear_list(self):  # 清空列表
        self.ips = []  # 清空顺序
        self.ip_set = set()  # 清空集合
        self.listbox.delete(0, "end")  # 清空界面
        self.rebuild_multi_menu()  # 菜单回到空
        self.refresh_count()  # 数量为 0
        self.append_log("多 IP 列表已清空。")  # 记录

    def selected_ips(self):  # 选中的地址
        hosts = []  # 结果
        for index in self.listbox.curselection():  # 选中下标
            ip = self.ips[index]  # 地址
            if is_ipv4(ip):  # 再校验
                hosts.append(ip)  # 加入
        return hosts  # 返回

    def ping_all_added(self):  # 探测全部已加入的地址
        self.start_ping(list(self.ips), "多IP全部服务器")  # 并发

    def ping_selected(self):  # 探测选中地址
        hosts = self.selected_ips()  # 读取
        if not hosts:  # 没有选中
            messagebox.showwarning("没有选中", "先在列表中选中一个或多个地址。")  # 提示
            return  # 返回
        self.start_ping(hosts, "多IP选中服务器")  # 并发

    def ping_custom_range(self):  # 按起止展开
        try:  # 展开可能失败
            hosts = expand_ipv4_range(self.start_var.get().strip(), self.end_var.get().strip(), MAX_RANGE)  # 连续地址
        except ValueError as exc:  # 不合法
            messagebox.showwarning("连续网段", str(exc))  # 显示原因
            return  # 不开始
        self.start_ping(hosts, "连续网段 {} 到 {}".format(hosts[0], hosts[-1]))  # 并发

    def ping_octet_range(self, first, last):  # 同网段最后一段
        try:  # 展开可能失败
            hosts = expand_last_octet(self.start_var.get().strip(), first, last, MAX_RANGE)  # 前三段加最后一段
        except ValueError as exc:  # 不合法
            messagebox.showwarning("连续网段", str(exc))  # 显示原因
            return  # 不开始
        self.start_ping(hosts, "同网段 {}.{} 到 {}".format(".".join(hosts[0].split(".")[:3]), first, last))  # 并发

    def stop_ping(self):  # 停止后续地址
        self.stop_event.set()  # 正在等待的任务结束后不再开始新地址
        self.append_log("已请求停止。已经发出的 4 个包会等到本次超时。")  # 说明

    def report_dir(self):  # 报告目录
        path = os.path.join(app_base_dir(), "reports")  # 固定目录
        if not os.path.isdir(path):  # 不存在
            os.makedirs(path)  # 创建
        return path  # 返回

    def save_report(self):  # 保存 UTF-8 报告
        name = "SaoMiao_Ping_report_{}.txt".format(time.strftime("%Y%m%d_%H%M%S"))  # 文件名
        path = os.path.join(self.report_dir(), name)  # 路径
        lines = ["SaoMiao_Ping 日志报告", "版本: {}".format(VERSION), "生成时间: {}".format(time.strftime("%Y-%m-%d %H:%M:%S")), "操作系统: {}".format(platform.platform()), "Ping 方式: icmplib 原始 ICMP，每台 {} 个包，同时最多 {} 台".format(PING_COUNT, PING_CONCURRENCY), "多IP列表:"]  # 报告头
        if self.ips:  # 有地址
            for ip in self.ips:  # 逐个
                lines.append("  {}".format(ip))  # 写入
        else:  # 空列表
            lines.append("  (空)")  # 标明为空
        lines.append("")  # 空行
        lines.append("---------- 运行日志 ----------")  # 日志标题
        lines.append("")  # 空行
        lines.extend(self.log_lines)  # 全部日志
        data = b"\xef\xbb\xbf" + ("\r\n".join(lines) + "\r\n").encode("utf-8")  # BOM 和换行
        try:  # 写文件
            handle = open(path, "wb")  # 打开
            try:  # 保证关闭
                handle.write(data)  # 写入
            finally:  # 关闭
                handle.close()  # 释放
        except OSError as exc:  # 写失败
            messagebox.showerror("保存失败", "无法写入报告：{}".format(exc))  # 提示
            return  # 返回
        self.append_log("日志报告已保存：{}".format(path))  # 记录路径
        if messagebox.askyesno("日志报告", "报告已保存：\n{}\n\n是否立即打开？".format(path)):  # 询问打开
            try:  # 打开可能失败
                os.startfile(path)  # 用系统程序打开
            except OSError as exc:  # 失败
                messagebox.showerror("无法打开", "{}".format(exc))  # 提示

    def open_report_dir(self):  # 打开报告目录
        try:  # 可能失败
            os.startfile(self.report_dir())  # 打开
        except OSError as exc:  # 失败
            messagebox.showerror("无法打开", "{}".format(exc))  # 提示

    def clear_log(self):  # 清空日志
        self.log_lines = []  # 清空缓存
        try:  # 控件可能不存在
            self.log_text.delete("1.0", "end")  # 清空显示
        except tk.TclError:  # 已关闭
            self.alive = False  # 停止
            return  # 返回
        self.append_log("日志已清空。")  # 留一行

    def on_close(self):  # 关闭窗口
        self.alive = False  # 停止刷新
        self.stop_event.set()  # 通知后台
        self.root.destroy()  # 关闭


def console_print(text):  # 自测输出
    data = (text + "\n").encode("utf-8", "replace")  # 编码
    try:  # 写二进制输出
        sys.stdout.buffer.write(data)  # 避免代码页问题
    except (AttributeError, OSError):  # 没有 buffer
        sys.stdout.write(text + "\n")  # 普通输出


def run_self_test():  # 检查多行地址、4 个包，并且只探测回环
    valids, invalids = parse_ip_lines("10.0.0.2\n10.0.0.3\n# 注释\n10.0.0.2\ncalc.exe")  # 竖行、重复和无效文字
    if valids != ["10.0.0.2", "10.0.0.3"] or invalids != ["calc.exe"]:  # 重复只留一次，无效不执行
        raise RuntimeError("多行地址解析不正确")  # 失败
    comma_hosts, comma_bad = parse_ip_tokens("10.0.0.2,10.0.0.3,10.0.0.4")  # 第一行用英文逗号分开
    if comma_hosts != ["10.0.0.2", "10.0.0.3", "10.0.0.4"] or comma_bad != []:  # 三个地址都要测
        raise RuntimeError("英文逗号没有分成多个 IP")  # 失败
    if PING_COUNT != 4:  # 发包数量固定为 4
        raise RuntimeError("Ping 包数量不是 4")  # 失败
    host = asyncio.run(ping_address("127.0.0.1"))  # 只探测本机回环
    if int(host.packets_sent) != 4 or int(host.packets_received) < 1 or not host.is_alive:  # 必须发出 4 个并收到回复
        raise RuntimeError("回环没有完成 4 个 ICMP 包")  # 失败
    root = tk.Tk()  # 隐藏界面
    root.withdraw()  # 不抢前台
    app = App(root)  # 创建窗口
    root.update()  # 完成布局
    app.bulk_text.insert("1.0", "10.0.0.8\n10.0.0.9\n")  # 填入两个不会去探测的文档地址
    got, bad = app.bulk_addresses()  # 读取大框
    if got != ["10.0.0.8", "10.0.0.9"] or bad != []:  # 大框应按行读取
        raise RuntimeError("界面多行框没有读出地址")  # 失败
    if int(app.bulk_text.cget("height")) != 8:  # 必须是长方形多行框
        raise RuntimeError("多行地址框不存在")  # 失败
    if str(app.result_panel.pack_info().get("side")) != "right":  # 红绿灯必须在最右边
        raise RuntimeError("结果界面不在最右边")  # 失败
    app.prepare_cards(["10.0.0.2", "10.0.0.3", "10.0.0.4"])  # 模拟一行里的三个地址
    app.apply_ping("10.0.0.2", True, "可以 Ping 通（收到 4 次回复，发送 4 个，平均 1.0 ms）")  # 第一台绿灯
    app.apply_ping("10.0.0.3", False, "无法 Ping 通（发送 4 个，收到 0 次回复）")  # 第二台红灯
    app.apply_ping("10.0.0.4", True, "可以 Ping 通（收到 4 次回复，发送 4 个，平均 1.0 ms）")  # 第三台绿灯
    if app.card_rows[0]["state"].cget("text") != "Ping通":  # 绿灯旁边要有汉字
        raise RuntimeError("Ping通没有写汉字")  # 失败
    if app.card_rows[0]["lamp"].itemcget(app.card_rows[0]["oval"], "fill") != GREEN:  # 通的是绿色圆灯
        raise RuntimeError("Ping通没有亮绿灯")  # 失败
    if app.card_rows[1]["state"].cget("text") != "未Ping通":  # 红灯旁边要有汉字
        raise RuntimeError("未Ping通没有写汉字")  # 失败
    if app.card_rows[1]["lamp"].itemcget(app.card_rows[1]["oval"], "fill") != RED:  # 不通的是红色圆灯
        raise RuntimeError("未Ping通没有亮红灯")  # 失败
    if len(app.card_rows) != 3:  # 三个逗号地址都要有一行
        raise RuntimeError("三个地址没有都显示在右侧")  # 失败
    app.alive = False  # 停止刷新
    root.destroy()  # 关闭
    console_print("PING SELF-TEST OK")  # 通过


def main():  # 入口
    if "--self-test" in sys.argv:  # 自测
        run_self_test()  # 执行
        return  # 退出
    root = tk.Tk()  # 主窗口
    App(root)  # 界面
    root.mainloop()  # 消息循环


if __name__ == "__main__":  # 直接运行
    try:  # 捕获异常
        main()  # 启动
    except Exception:  # 未处理异常
        write_error_log(traceback.format_exc())  # 写日志
        raise  # 继续抛出
