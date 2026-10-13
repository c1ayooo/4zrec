# 红帆OA医院版sql注入

红帆OA医院版 ｜ SQL注入 ｜ —
- **请求**：`GET /iOffice/prg/set/wss/wssRtSyn.asmx?op=SubmitShowMsg HTTP/1.1`
- **响应特征**：-1 ^(?=.*?SubmitShowMsg)(?=.*?ServerHost)(?=.*?SubmitShowMsgResponse).*?$