// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// +build !windows

package vxlan

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/projectcalico/node/pkg/vxlan/ip"
	log "github.com/sirupsen/logrus"

	"golang.org/x/net/context"
)

const (
	defaultVNI = 1
)

type ExternalInterface struct {
	Iface     *net.Interface
	IfaceAddr net.IP
	ExtAddr   net.IP
}

type VXLANBackend struct {
	extIface *ExternalInterface
}

func LookupExtIface(ifname string, ifregex string) (*ExternalInterface, error) {
	var iface *net.Interface
	var ifaceAddr net.IP
	var err error

	if len(ifname) > 0 {
		if ifaceAddr = net.ParseIP(ifname); ifaceAddr != nil {
			log.Infof("Searching for interface using %s", ifaceAddr)
			iface, err = ip.GetInterfaceByIP(ifaceAddr)
			if err != nil {
				return nil, fmt.Errorf("error looking up interface %s: %s", ifname, err)
			}
		} else {
			iface, err = net.InterfaceByName(ifname)
			if err != nil {
				return nil, fmt.Errorf("error looking up interface %s: %s", ifname, err)
			}
		}
	} else if len(ifregex) > 0 {
		// Use the regex if specified and the iface option for matching a specific ip or name is not used
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("error listing all interfaces: %s", err)
		}

		// Check IP
		for _, ifaceToMatch := range ifaces {
			ifaceIP, err := ip.GetIfaceIP4Addr(&ifaceToMatch)
			if err != nil {
				// Skip if there is no IPv4 address
				continue
			}

			matched, err := regexp.MatchString(ifregex, ifaceIP.String())
			if err != nil {
				return nil, fmt.Errorf("regex error matching pattern %s to %s", ifregex, ifaceIP.String())
			}

			if matched {
				ifaceAddr = ifaceIP
				iface = &ifaceToMatch
				break
			}
		}

		// Check Name
		if iface == nil && ifaceAddr == nil {
			for _, ifaceToMatch := range ifaces {
				matched, err := regexp.MatchString(ifregex, ifaceToMatch.Name)
				if err != nil {
					return nil, fmt.Errorf("regex error matching pattern %s to %s", ifregex, ifaceToMatch.Name)
				}

				if matched {
					iface = &ifaceToMatch
					break
				}
			}
		}

		// Check that nothing was matched
		if iface == nil {
			var availableFaces []string
			for _, f := range ifaces {
				ip, _ := ip.GetIfaceIP4Addr(&f) // We can safely ignore errors. We just won't log any ip
				availableFaces = append(availableFaces, fmt.Sprintf("%s:%s", f.Name, ip))
			}

			return nil, fmt.Errorf("Could not match pattern %s to any of the available network interfaces (%s)", ifregex, strings.Join(availableFaces, ", "))
		}
	} else {
		log.Info("Determining IP address of default interface")
		if iface, err = ip.GetDefaultGatewayIface(); err != nil {
			return nil, fmt.Errorf("failed to get default interface: %s", err)
		}
	}

	if ifaceAddr == nil {
		ifaceAddr, err = ip.GetIfaceIP4Addr(iface)
		if err != nil {
			return nil, fmt.Errorf("failed to find IPv4 address for interface %s", iface.Name)
		}
	}

	log.Infof("Using interface with name %s and address %s", iface.Name, ifaceAddr)

	if iface.MTU == 0 {
		return nil, fmt.Errorf("failed to determine MTU for %s interface", ifaceAddr)
	}

	var extAddr net.IP

	if extAddr == nil {
		log.Infof("Defaulting external address to interface address (%s)", ifaceAddr)
		extAddr = ifaceAddr
	}

	return &ExternalInterface{
		Iface:     iface,
		IfaceAddr: ifaceAddr,
		ExtAddr:   extAddr,
	}, nil
}

func New(ctx context.Context) (*VXLANBackend, error) {
	extIface, err := LookupExtIface("", "")
	if err != nil {
		return nil, err
	}
	backend := &VXLANBackend{
		extIface: extIface,
	}

	dev, err := backend.EnsureDevice(ctx)
	if err != nil {
		return nil, err
	}

	nw, err := newNetwork(dev)
	if err != nil {
		return nil, err
	}

	go nw.Run(ctx)

	<-ctx.Done()
	return backend, nil
}

func (be *VXLANBackend) EnsureDevice(ctx context.Context) (*vxlanDevice, error) {
	// Parse our configuration
	cfg := struct {
		VNI           int
		Port          int
		GBP           bool
		DirectRouting bool
	}{
		VNI: defaultVNI,
	}
	log.Infof("VXLAN config: VNI=%d Port=%d GBP=%v DirectRouting=%v", cfg.VNI, cfg.Port, cfg.GBP, cfg.DirectRouting)

	devAttrs := vxlanDeviceAttrs{
		vni:       uint32(cfg.VNI),
		name:      fmt.Sprintf("cxlan.%v", cfg.VNI),
		vtepIndex: be.extIface.Iface.Index,
		vtepAddr:  be.extIface.IfaceAddr,
		vtepPort:  cfg.Port,
		gbp:       cfg.GBP,
	}

	dev, err := newVXLANDevice(&devAttrs)
	if err != nil {
		return nil, err
	}
	dev.directRouting = cfg.DirectRouting
	log.Infof("Created device: %#v", dev)
	return dev, nil
}

// So we can make it JSON (un)marshalable
type hardwareAddr net.HardwareAddr

func (hw hardwareAddr) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", net.HardwareAddr(hw))), nil
}

func (hw *hardwareAddr) UnmarshalJSON(bytes []byte) error {
	if len(bytes) < 2 || bytes[0] != '"' || bytes[len(bytes)-1] != '"' {
		return fmt.Errorf("error parsing hardware addr")
	}

	bytes = bytes[1 : len(bytes)-1]

	mac, err := net.ParseMAC(string(bytes))
	if err != nil {
		return err
	}

	*hw = hardwareAddr(mac)
	return nil
}
