package intel

// kevCatalogFixture is a two-entry slice of the CISA KEV feed, newest last in
// the payload so the source's own sort is exercised by the test.
const kevCatalogFixture = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2024.06.01",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "Apache Log4j2 contains a vulnerability where JNDI features used in configuration do not protect against attacker-controlled LDAP servers.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known",
      "notes": "https://logging.apache.org/log4j/2.x/security.html; https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    {
      "cveID": "CVE-2024-3400",
      "vendorProject": "Palo Alto Networks",
      "product": "PAN-OS",
      "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
      "dateAdded": "2024-04-12",
      "shortDescription": "Palo Alto Networks PAN-OS GlobalProtect feature contains a command injection vulnerability.",
      "requiredAction": "Apply mitigations per vendor instructions.",
      "dueDate": "2024-04-19",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "https://security.paloaltonetworks.com/CVE-2024-3400"
    }
  ]
}`

// oscsListFixture and oscsDetailFixture mirror the OSCS list/detail pair.
const oscsListFixture = `{
  "data": {"total": 1, "data": [
    {"mps": "MPS-2024-0001", "url": "/hd/MPS-2024-0001", "intelligence_type": 1, "is_push": 1}
  ]},
  "success": true, "code": 200, "info": "ok"
}`

const oscsDetailFixture = `{
  "data": [{
    "vuln_no": "MPS-2024-0001",
    "vuln_title": "Apache Struts2 远程代码执行漏洞",
    "description": "Struts2 的 OGNL 表达式解析存在缺陷，攻击者可构造恶意请求在目标服务器上执行任意代码。",
    "level": "High",
    "cve_id": "CVE-2024-53677",
    "publish_time": 1718000000000,
    "soulution_data": ["升级到安全版本", "临时关闭受影响接口"],
    "references": [{"name": "官方公告", "url": "https://struts.apache.org/announce"}]
  }],
  "success": true, "code": 200, "info": "ok"
}`

// chaitinListFixture mirrors the real stack.chaitin.com list envelope. Note
// the site wraps a successful payload in `{"msg":"success","data":{...}}` with
// no numeric code, and marks a throttled request with HTTP 465 plus an HTML
// body rather than JSON — the source fetches one page per poll for that reason.
const chaitinListFixture = `{
  "msg": "success",
  "data": {
    "count": 421906,
    "next": "http://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset=15&search=CT-",
    "list": [{
      "id": "6e96c92b-73c4-47aa-8724-92b41bf98785",
      "title": "CVE-2026-86467",
      "summary": "Apache Airflow Amazon provider：SAML 登录流程未将认证响应绑定到发起该流程的浏览器。",
      "severity": "高危",
      "ct_id": "CT-2026-86467",
      "cve_id": "CVE-2026-86467",
      "references": "https://example.com/advisory\nhttps://example.com/patch",
      "created_at": "2026-10-19T10:20:11Z"
    }]
  }
}`

// qianxinOneDayFixture mirrors the real one-day envelope. Two things here are
// easy to get wrong and both were: the success code is 10000 (not 0 or 200),
// and the full new-advisory list is `vuln_add` — `key_vuln_add` is only the
// vendor-highlighted subset (76 vs 1 on a live call).
const qianxinOneDayFixture = `{
  "status": 10000,
  "message": "success",
  "data": {
    "vuln_add_count": 2,
    "key_vuln_add_count": 1,
    "vuln_add": [
      {
        "id": 521950,
        "vuln_name": "Modern Events Calendar SQL注入漏洞(CVE-2026-96534)",
        "qvd_code": "QVD-2026-87006",
        "cve_code": "CVE-2026-96534",
        "publish_time": "2026-10-18",
        "description": "插件在使用参数构建 SQL 语句之前未对其进行过滤和转义。",
        "rating_level": "高危",
        "threat_category": "代码执行,信息泄露",
        "poc_flag": 1,
        "patch_flag": 0,
        "tag": [{"id": 3, "name": "WordPress"}]
      },
      {
        "id": 521951,
        "vuln_name": "某组件信息泄露漏洞",
        "qvd_code": "QVD-2026-87007",
        "cve_code": "",
        "publish_time": "2026-10-18",
        "description": "描述",
        "rating_level": "中风险",
        "threat_category": "信息泄露",
        "poc_flag": 0,
        "patch_flag": 1,
        "tag": []
      }
    ],
    "key_vuln_add": [
      {
        "id": 521950,
        "vuln_name": "Modern Events Calendar SQL注入漏洞(CVE-2026-96534)",
        "qvd_code": "QVD-2026-87006",
        "cve_code": "CVE-2026-96534",
        "publish_time": "2026-10-18",
        "rating_level": "高危",
        "tag": []
      }
    ]
  }
}`

// threatbookHomeFixture mirrors the real homePage payload. `riskLevel` uses the
// "-风险" wording (高风险), not the "-危" wording other feeds use, and the
// premium list carries no risk level or publish time at all.
const threatbookHomeFixture = `{
  "response_code": 0,
  "data": {
    "highrisk": [
      {
        "id": "XVE-2026-81746",
        "vuln_name_zh": "Apache Camel 远程代码执行漏洞",
        "vuln_update_time": "2026-10-20",
        "vuln_publish_time": "2026-10-19",
        "affects": ["Apache软件基金会>Apache Camel"],
        "pocExist": true,
        "premium": false,
        "solution": true,
        "riskLevel": "高风险"
      }
    ],
    "premium": [
      {"id": "XVE-2023-2478", "vuln_name_zh": "Atlassian Confluence 模板注入代码执行漏洞", "free": true, "vuln_update_time": "2026-06-06"}
    ]
  }
}`

// seebugListFixture is a trimmed copy of the real advisory table markup: two
// anchors per row (the SSV id first, the title second), the severity both as a
// CSS class and in data-original-title, and the CVE on an icon.
const seebugListFixture = `<table class="table sebug-table table-vul-list"><tbody>
  <tr>
    <td><a href="/vuldb/ssvid-99969">SSV-99969</a></td>
    <td class="text-center datetime hidden-sm hidden-xs">2026-05-08</td>
    <td class="text-center hidden-sm hidden-xs">
      <div class="vul-level high" data-toggle="tooltip" data-original-title="高危" ><span class="step1"></span></div>
    </td>
    <td class="vul-title-wrapper"><a class="vul-title" title="Linux 内核提权 Dirty Frag" href="/vuldb/ssvid-99969">Linux 内核提权 Dirty Frag</a></td>
    <td class="text-center hidden-sm hidden-xs ">
      <i class="fa fa-id-card  text-muted " data-toggle="tooltip" data-original-title="无 CVE"></i>
      <i class="fa fa-rocket text-muted " data-toggle="tooltip" data-original-title="无 PoC"></i>
    </td>
  </tr>
  <tr>
    <td><a href="/vuldb/ssvid-99968">SSV-99968</a></td>
    <td class="text-center datetime hidden-sm hidden-xs">2026-05-07</td>
    <td class="text-center hidden-sm hidden-xs">
      <div class="vul-level medium" data-toggle="tooltip" data-original-title="中危" ><span class="step1"></span></div>
    </td>
    <td class="vul-title-wrapper"><a class="vul-title" title="某管理系统 SQL 注入" href="/vuldb/ssvid-99968">某管理系统 SQL 注入</a></td>
    <td class="text-center hidden-sm hidden-xs ">
      <i class="fa fa-id-card  text-muted " data-toggle="tooltip" data-original-title="CVE-2026-11111、CVE-2026-22222"></i>
      <i class="fa fa-rocket text-muted " data-toggle="tooltip" data-original-title="有 PoC"></i>
    </td>
  </tr>
</tbody></table>`
