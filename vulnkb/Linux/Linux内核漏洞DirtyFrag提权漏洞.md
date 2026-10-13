# Linux内核漏洞DirtyFrag提权漏洞

- **系统**：Linux　|　**类型**：权限提升　|　**CVE**：—

**请求体 / payload**
```
+ 路径一：ESP / XFRM（首选）
**目标：覆盖 /usr/bin/su（SUID root）**
脚本引用链接：[https://pan.quark.cn/s/fd1f96dbd6e5](https://pan.quark.cn/s/fd1f96dbd6e5)
执行
gcc -O0 -Wall -o exp exp.c -lutil && ./exp
```

**其他**
- 版本: | 发行版 | 版本 | 内核版本
| :--- | :--- | :---
| Ubuntu | 24.04.4 | 6.17.0-23-generic
| RHEL | 10.1 | 6.12.0-124.49.1.el10_1.x86_64
| openSUSE Tumbleweed | 最新版本 | 7.0.2-1-default
| CentOS Stream | 10 | 6.12.0-224.el10.x86_64
| AlmaLinux | 10 | 6.12.0-124.52.3.el10_1.x86_64
| Fedora | 44 | 6.19.14-300.fc44.x86_64
- 原理: 利用内核网络子系统（XFRM / rxrpc）的页缓存写入漏洞，把 /usr/bin/su或 /etc/passwd改成“允许直接拿 root”，最后通过 su拿到 root shell。
- 核心原理: 1. **unshare(USER+NET)**
+ → 获得 **CAP_NET_RAW**（不需要真实 root）
2. **Netlink + XFRM（IPsec）**
    - 创建大量 **XFRM SA（安全关联）**
    - 把 **要写入的 shellcode** 编码进 seq_hi（ESN replay 高位）
3. **UDP + splice + vmsplice**
    - 把 /usr/bin/su的 **页缓存页** 当成“密文”
    - 发给内核“解密”
    - 内核错误地用我们控制的 seq_hi写回页缓存
4. **结果**
+ /usr/bin/su 前 192 字节
↓
被替换成 一个静态 x86_64 root shell ELF
5. **执行**
+ su -
+ → 直接弹 **root shell**
+ 路径二
- 目标：修改 /etc/passwd## 核心原理: 1. **AF_RXRPC + rxkad 加密**
    - 内核使用 pcbc(fcrypt)解密网络包
    - 解密结果会写回 **页缓存**
2. **用户态离线爆破**
    - 读取 /etc/passwd第 1 行（root 条目）
    - 暴力找 8 字节 key
    - 使得解密后变成：
    - root::0:0:...:/root:/bin/bash
3. **三次 splice 写入**
    - 分别改：
        * uid
        * gid
        * shell 字段
4. **PAM nullok**
    - 空密码 + pam_unix.so nullok
    - su直接成功
- 统一提权流程（chain）: 普通用户 (uid=1000)
        ↓
┌───────────────┐
│ ESP 路径      │ ← 覆盖 /usr/bin/su
│ rxrpc 路径    │ ← 清空 root 密码
└───────────────┘
        ↓
run_root_pty()
        ↓
fork + PTY + su
        ↓
root shell 🎉
大致流程图为：