# OpenClawAI漏洞：零点击远程代码执行与间接注入

- **系统**：OpenClawAI　|　**类型**：命令执行　|　**CVE**：—

**请求体 / payload**
```
无需浏览器即可利用，通过 Python 的 `python-socketio` 库直接对接后端总线，完全绕过前端界面。
环境依赖安装：
pip install "python-socketio[asyncio]" aiohttp
脚本伪装成合法前端客户端，连接代理总线，注入指令 payload，让代理以高权限系统任务执行。
import asyncio
import socketio
import json
```

**其他**
- 前言：“自主代理” 带来的全新攻击面: 2026 年当下，OpenClaw AI（常以 OpenClaw “自主代理” 形态部署）已成为开发者搭建本地部署、自动化编程助手的主流选择。它打出的卖点十分诱人：一款能本地运行、管理文件、自动化工作流的 AI 工具。
但在安全圈看来，OpenClaw 代表着一种极度危险的新模式 ——**未做过滤的沙箱**。
安装 OpenClaw 时，你装的不只是一个聊天机器人，而是一个自带以下权限的服务：
* 本地文件系统读写权限
* 无限制联网爬取数据权限
* 系统命令执行权限（“上帝模式” 下默认自动授权）
传统渗透测试思路在 OpenClaw 面前基本失效，因为大家习惯找 SQL 注入、XSS 漏洞，却忽略了**语义逻辑漏洞**—— 这类漏洞能把贴心助手直接变成潜伏在设备里的恶意程序。
本篇不是理论科普，而是实打实的技术手册。我会一步步还原完整攻击链路：从端口扫描到拿下完整远程代码执行（RCE）
- 第一阶段：环境搭建与攻击面梳理: ⚠️ 警告：切勿在主力工作机上做测试，本次漏洞利用会真实操作文件系统。
- 1.1 实验环境架构: 为安全审计 OpenClaw，需要搭建隔离环境，模拟开发者常用配置并拦截外发流量。
* 目标机：运行最新版 OpenClaw 的 Docker 容器或虚拟机
* 攻击机：Kali Linux 或自定义 Python 环境
* 流量监听：Burp Suite（透明代理模式）或 Wireshark 监听本地回环
- 1.2 发现：隐藏的高危端口: OpenClaw 对外只暴露前端界面（通常在 3000 或 8080 端口），但标准 nmap 扫描能挖出真正的攻击面。
```plain
- 对本地实例执行全端口扫描: nmap -p- -sV localhost
```
扫描结果示例：
```plain
PORT STATE SERVICE VERSION
3000/tcp open http Node.js Express (前端界面)
8000/tcp open http FastAPI (向量数据库接口)
```
关键突破口是**3000 端口**：它除了运行 React 前端，还承载着 “代理总线” 的 WebSocket（Socket.IO）通信接口，这是 OpenClaw 的核心中枢，也是我们发现首个高危漏洞的位置。
***
- 第二阶段：协议逆向分析（CVE-2026-25253）: CVE-2026-25253 为高危漏洞，成因是 OpenClaw 的 WebSocket 握手环节**身份验证机制存在严重缺陷**。