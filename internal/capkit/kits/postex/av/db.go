package av

// defaultProducts is the built-in AV/EDR fingerprint database (docs §4.12 —
// "杀软识别指纹库").
//
// It covers the products most likely to be met during an authorized engagement
// on Windows and Linux. Each entry lists the observable artifacts that identify
// it: process images, service names, kernel drivers, registry keys, files.
// One signature matching is enough for detection.
//
// Notes are decision support for the operator (what the product watches for).
// They deliberately contain NO bypass technique — the payload/boundary stays
// out of the library.
var defaultProducts = []Product{
	// ---- Windows EDR / NGAV ----
	{
		ID: "ms-defender", Name: "Microsoft Defender for Endpoint", Vendor: "Microsoft",
		Category: CatEDR, Platform: "windows",
		Processes: []string{"MsMpEng.exe", "MpCmdRun.exe", "SenseIR.exe", "SenseNdr.exe"},
		Services:  []string{"WinDefend", "WdNisSvc", "Sense", "MsSense", "WdBoot"},
		Drivers:   []string{"WdFilter.sys", "WdNisDrv.sys", "mpsdrv.sys", "SysmonDrv.sys"},
		Registry:  []string{`HKLM\SOFTWARE\Microsoft\Windows Defender`, `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`},
		Notes:     "AMSI 由本机提供；注册表与进程名常驻。关注命令行审计与内存扫描。",
	},
	{
		ID: "crowdstrike-falcon", Name: "CrowdStrike Falcon", Vendor: "CrowdStrike",
		Category: CatEDR, Platform: "windows",
		Processes: []string{"CSFalconService.exe", "CSFalconContainer.exe"},
		Services:  []string{"CSFalconService", "CSAgent"},
		Drivers:   []string{"csagent.sys", "crowdstrike.sys", "CsFirmwareAnalysis.sys"},
		Files:     []string{`C:\Windows\System32\drivers\csagent.sys`},
		Notes:     "内核级行为传感器 + 云端 ML；进程创建与镜像加载全量上报。",
	},
	{
		ID: "sentinelone", Name: "SentinelOne Singularity", Vendor: "SentinelOne",
		Category: CatEDR, Platform: "windows",
		Processes: []string{"SentinelOne.exe", "SentinelAgent.exe", "SentinelHelper.exe"},
		Services:  []string{"SentinelOne", "SentinelAgent"},
		Drivers:   []string{"SentinelDeviceGuard.sys", "SentinelMonitor.sys"},
		Notes:     "行为拦截为主，Rollback 功能会还原其判定的恶意变更。",
	},
	{
		ID: "carbon-black", Name: "VMware Carbon Black Cloud", Vendor: "VMware",
		Category: CatEDR, Platform: "windows",
		Processes: []string{"cb.exe", "RepMgr.exe", "RepUtils.exe"},
		Services:  []string{"CbDefense", "CarbonBlack"},
		Drivers:   []string{"cbk7.sys", "CbDeviceControl.sys", "CarbonBlackK.sys"},
		Notes:     "传感器上报进程树与模块加载；策略可阻断未签名可执行。",
	},
	{
		ID: "cylance", Name: "Blackberry CylancePROTECT", Vendor: "BlackBerry",
		Category: CatEDR, Platform: "windows",
		Processes: []string{"CylanceSvc.exe", "CylanceUI.exe"},
		Services:  []string{"CylanceSvc"},
		Drivers:   []string{"CyProtectDrv64.sys", "CyOptics.sys"},
		Notes:     "静态+AI 模型判定，预执行拦截，行为覆盖少于 EDR 同侪。",
	},
	{
		ID: "cortex-xdr", Name: "Palo Alto Cortex XDR", Vendor: "Palo Alto Networks",
		Category: CatEDR, Platform: "windows",
		Processes: []string{"cyserver.exe", "cytool.exe"},
		Services:  []string{"cyserver", "CyveraService"},
		Drivers:   []string{"cyvrfsfd.sys", "cyvrmtgn.sys"},
		Notes:     "与 Traps 技术同源；覆盖脚本拦截与进程注入检测。",
	},
	{
		ID: "symantec-ses", Name: "Broadcom Symantec Endpoint Security", Vendor: "Broadcom",
		Category: CatEPP, Platform: "windows",
		Processes: []string{"sisipsutil.exe", "SymCorpUI.exe", "ccSvcHst.exe"},
		Services:  []string{"SepMasterService", "Symantec AntiVirus"},
		Drivers:   []string{"symevent.sys", "SRTSP.sys", "SYMEFASI64.sys"},
		Notes:     "传统 AV + 部分 EDR 行为；SONAR 做启发式。",
	},
	{
		ID: "mcafee-ens", Name: "Trellix Endpoint Security", Vendor: "Trellix",
		Category: CatEPP, Platform: "windows",
		Processes: []string{"mcshield.exe", "mfehcsr.exe", "shstat.exe"},
		Services:  []string{"McAfeeFramework", "McShield", "mfemms"},
		Drivers:   []string{"mfehidk.sys", "mfeavfk.sys", "mfeelamk.sys"},
		Notes:     "访问扫描 + 主机防火墙，进程创建时实时扫描。",
	},

	// ---- Windows logging ----
	{
		ID: "sysmon", Name: "Sysinternals Sysmon", Vendor: "Microsoft",
		Category: CatLogging, Platform: "windows",
		Services: []string{"Sysmon64", "Sysmon"},
		Drivers:  []string{"SysmonDrv.sys", "Sysmon64.sys"},
		Registry: []string{`HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64`},
		Notes:    "记录进程创建（含命令行）、镜像加载、网络连接、注册表变更到 Windows 日志。",
	},
	{
		ID: "windows-firewall", Name: "Windows Defender Firewall", Vendor: "Microsoft",
		Category: CatFW, Platform: "windows",
		Processes: []string{"svchost.exe"},
		Services:  []string{"MpsSvc", "BFE"},
		Notes:     "主机防火墙；出站规则可阻断 C2 与横向网络连接。",
	},

	// ---- Linux ----
	{
		ID: "osquery", Name: "Fleet osquery", Vendor: "Fleet",
		Category: CatLogging, Platform: "linux",
		Processes: []string{"osqueryd", "orbit"},
		Services:  []string{"osqueryd"},
		Files:     []string{"/etc/osquery/osquery.conf", "/usr/bin/osqueryd", "/opt/orbit/bin/orbit"},
		Notes:     "SQL 驱动的清单采集：进程、套接字、系统扩展；按计划查询并上报。",
	},
	{
		ID: "auditbeat", Name: "Elastic Auditbeat", Vendor: "Elastic",
		Category: CatLogging, Platform: "linux",
		Processes: []string{"auditbeat", "filebeat"},
		Services:  []string{"auditbeat"},
		Files:     []string{"/etc/auditbeat/auditbeat.yml", "/usr/share/auditbeat/bin/auditbeat"},
		Notes:     "进程与文件完整性事件，直送 Elastic；进程执行可被记录。",
	},
	{
		ID: "falco", Name: "Falco runtime security", Vendor: "Sysdig",
		Category: CatEDR, Platform: "linux",
		Processes: []string{"falco", "falcoctl"},
		Services:  []string{"falco"},
		Drivers:   []string{"falco.ko", "falcosecurity_scap.ko"},
		Files:     []string{"/etc/falco/falco_rules.yaml", "/etc/falco/rules.d"},
		Notes:     "eBPF/kmod 系统调用级规则引擎；容器环境默认即装。",
	},
	{
		ID: "wazuh", Name: "Wazuh agent", Vendor: "Wazuh",
		Category: CatEPP, Platform: "linux",
		Processes: []string{"wazuh-agentd", "wazuh-execd", "wazuh-syscheckd"},
		Services:  []string{"wazuh-agent"},
		Files:     []string{"/var/ossec/etc/ossec.conf", "/var/ossec/bin/wazuh-control"},
		Notes:     "主机 IDS + FIM + 漏洞检测；syscheck 会记录文件哈希变化。",
	},
	{
		ID: "crowdstrike-linux", Name: "CrowdStrike Falcon Sensor (Linux)", Vendor: "CrowdStrike",
		Category: CatEDR, Platform: "linux",
		Processes: []string{"falcon-sensor"},
		Services:  []string{"falcon-sensor"},
		Drivers:   []string{"falcon_lsm_sensor_ebpf.ko", "falcon_nf_netcontainers.ko"},
		Files:     []string{"/opt/CrowdStrike/falcond"},
		Notes:     "eBPF 内核传感器；与 Windows 端共用云端检测逻辑。",
	},
	{
		ID: "trellix-linux", Name: "Trellix Endpoint Security for Linux", Vendor: "Trellix",
		Category: CatEPP, Platform: "linux",
		Processes: []string{"mfefsd", "mfefwcore"},
		Services:  []string{"mfetpd", "mfefsd"},
		Files:     []string{"/opt/McAfee/agent", "/etc/cma.d"},
		Notes:     "进程执行拦截 + FIM；策略自 McAfee ePO。",
	},
	{
		ID: "ossec-hids", Name: "OSSEC HIDS", Vendor: "AT&T Cybersecurity",
		Category: CatEPP, Platform: "linux",
		Processes: []string{"ossec-analysisd", "ossec-logcollector", "ossec-remoted"},
		Services:  []string{"ossec"},
		Files:     []string{"/var/ossec/rules", "/var/ossec/logs/alerts/alerts.log"},
		Notes:     "日志分析 + rootkit 检测 + 主动响应；可执行阻断脚本。",
	},
	{
		ID: "aide", Name: "AIDE file integrity", Vendor: "GPL-2.0",
		Category: CatLogging, Platform: "linux",
		Processes: []string{},
		Files:     []string{"/etc/aide.conf", "/var/lib/aide/aide.db", "/usr/bin/aide"},
		Notes:     "定时文件完整性基线比对；不会实时拦截，但会暴露改动。",
	},
}
