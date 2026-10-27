// Package capkitpd is the optional ProjectDiscovery adapter module.
//
// Keep this module separate from capkit: the core kits must stay
// dependency-light. Implement the provider interfaces used by reconkit here
// (subfinder, dnsx, naabu, katana) and keep heavyweight imports out of the
// public core.
package capkitpd
