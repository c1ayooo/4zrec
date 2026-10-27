// Deprecated: 迁移到 kits/postex/internalnet，本包仅作兼容，M3 后移除。
// 只做类型别名与函数变量转发，不含任何实现；新代码请直接 import 新路径。
package internalnetkit

import "github.com/c1ayooo/4zrec/internal/capkit/kits/postex/internalnet"

type (
	ARPEntry       = internalnet.ARPEntry
	Adapter        = internalnet.Adapter
	Capability     = internalnet.Capability
	DiscoveredHost = internalnet.DiscoveredHost
	DomainInfo     = internalnet.DomainInfo
	HostDiscovery  = internalnet.HostDiscovery
	Ipconfig       = internalnet.Ipconfig
	Listener       = internalnet.Listener
	LocalInfo      = internalnet.LocalInfo
	NetInterface   = internalnet.NetInterface
	OpenPort       = internalnet.OpenPort
	PortScan       = internalnet.PortScan
	Process        = internalnet.Process
	Route          = internalnet.Route
	SMBResult      = internalnet.SMBResult
	Share          = internalnet.Share
)

var (
	Manifest      = internalnet.Manifest
	NewCapability = internalnet.NewCapability
)
