# XWiki存在SSTI模板注入漏洞

XWiki ｜ SQL注入 ｜ —
- **指纹**：`app="XWIKI-Platform"`

**Payload**
```
全局⾸选项-演示
可以注⼊和执⾏ Velocity 模板表达式
Payload:
{{velocity}} #set($x = 7 * 7) $x {{/velocity}}
服务器上会返回 49 ，确认模板执⾏
```
- **响应特征**：200