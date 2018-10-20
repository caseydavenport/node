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
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/node/pkg/calicoclient"
	"github.com/projectcalico/node/pkg/vxlan/ip"

	"syscall"
)

type network struct {
	dev *vxlanDevice
}

const (
	encapOverhead = 50
)

// func newNetwork(extIface *backend.ExternalInterface, dev *vxlanDevice, _ ip.IP4Net) (*network, error) {
func newNetwork(dev *vxlanDevice) (*network, error) {

	log.SetLevel(log.DebugLevel)
	nw := &network{
		// SimpleNetwork: backend.SimpleNetwork{
		// 	SubnetLease: lease,
		// 	ExtIface:    extIface,
		// },
		dev: dev,
	}

	return nw, nil
}

type syncerCBs struct {
	eventChan chan event
}

func (cb syncerCBs) OnStatusUpdated(status api.SyncStatus) {
}

func (cb syncerCBs) OnUpdates(updates []api.Update) {
	for _, upd := range updates {
		// Parse out the block affinity.
		ak := upd.Key.(model.BlockAffinityKey)
		log.Info("Sending block over channel to be processed")
		cb.eventChan <- event{
			CIDR: fmt.Sprintf("%s", ak.CIDR),
			Type: "add",
			Node: ak.Host,
		}
	}
}

// watchBlocks watches for blocks being assigned to this node and sends them
// over the provided channel.
func watchBlocks(bc chan event) {
	// Create a new syncer for block affinities.
	_, cc := calicoclient.CreateClient()
	type backendClientAccessor interface {
		Backend() bapi.Client
	}

	rts := []watchersyncer.ResourceType{
		{ListInterface: model.BlockAffinityListOptions{}},
	}
	cbs := syncerCBs{bc}
	syncer := watchersyncer.New(cc.(backendClientAccessor).Backend(), rts, cbs)
	go syncer.Start()
	log.Info("CASEY: Syncer started")
}

func (nw *network) Run(ctx context.Context) {
	log.Warn("CASEY: Running network code")
	wg := sync.WaitGroup{}

	log.Info("watching for new blocks")
	events := make(chan event)
	wg.Add(1)
	go func() {
		watchBlocks(events)
		log.Info("watchBlocks exited")
		wg.Done()
	}()

	defer wg.Wait()

	for {
		log.Info("Waiting for something to happen")
		select {
		case evtBatch := <-events:
			log.Warn("CASEY: Handling subnet event")
			nw.handleSubnetEvents(evtBatch)
			log.Warn("CASEY: Subnet event handled")
		case <-ctx.Done():
			log.Warn("CASEY: Network Run() complete")
			return
		}
	}
}

func (nw *network) MTU() int {
	// return nw.ExtIface.Iface.MTU - encapOverhead
	return 1400
}

type vxlanLeaseAttrs struct {
	VtepMAC hardwareAddr
}

type tmpAttrs struct {
	PublicIP net.IP
}

type event struct {
	Type string
	CIDR string
	Node string
}

func (nw *network) handleSubnetEvents(e event) {
	var vxlanAttrs vxlanLeaseAttrs
	log.Infof("Received event: %v", e)
	vxlanAttrs.VtepMAC = hardwareAddr(VTEPForNode(e.Node))
	neighborPublicIP := PublicIPForNode(e.Node)
	gw, dst, err := net.ParseCIDR(e.CIDR)
	if err != nil {
		// CASEY: TODO
		log.Fatal(err)
	}

	// CASEY: TODO - these are just to keep the code below happy.
	sn := ip.FromIP(gw)
	attrs := tmpAttrs{PublicIP: gw}

	// This route is used when traffic should be vxlan encapsulated
	vxlanRoute := netlink.Route{
		LinkIndex: nw.dev.link.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       dst,
		Gw:        gw,
	}
	vxlanRoute.SetFlag(syscall.RTNH_F_ONLINK)

	// CASEY: TODO
	directRoutingOK := false
	switch e.Type {
	case "add":
		if directRoutingOK {
			log.Infof("Adding direct route to subnet: %s PublicIP: %s", sn, attrs.PublicIP)

			// if err := netlink.RouteReplace(&directRoute); err != nil {
			// 	log.Errorf("Error adding route to %v via %v: %v", sn, attrs.PublicIP, err)
			// 	continue
			// }
		} else {
			log.Infof("adding subnet: %s PublicIP: %s VtepMAC: %s", sn, attrs.PublicIP, net.HardwareAddr(vxlanAttrs.VtepMAC))
			if err := nw.dev.AddARP(neighbor{IP: ip.FromIP(gw), MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
				log.Fatalf("AddARP failed: ", err)
			}

			if err := nw.dev.AddFDB(neighbor{IP: neighborPublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
				log.Error("AddFDB failed: ", err)

				// Try to clean up the ARP entry then continue
				if err := nw.dev.DelARP(neighbor{IP: ip.FromIP(gw), MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
					log.Error("DelARP failed: ", err)
				}

				log.Fatal(err)
			}

			// Set the route - the kernel would ARP for the Gw IP address if it hadn't already been set above so make sure
			// this is done last.
			log.Infof("Adding route")
			if err := netlink.RouteReplace(&vxlanRoute); err != nil {
				log.Errorf("failed to add vxlanRoute (%s -> %s): %v", vxlanRoute.Dst, vxlanRoute.Gw, err)

				// Try to clean up both the ARP and FDB entries then continue
				if err := nw.dev.DelARP(neighbor{IP: ip.FromIP(gw), MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
					log.Error("DelARP failed: ", err)
				}

				if err := nw.dev.DelFDB(neighbor{IP: neighborPublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
					log.Error("DelFDB failed: ", err)
				}

				log.Fatal(err)
			}
		}
	case "del":
		if directRoutingOK {
			log.Infof("Removing direct route to subnet: %s PublicIP: %s", sn, attrs.PublicIP)
			// if err := netlink.RouteDel(&directRoute); err != nil {
			// 	log.Errorf("Error deleting route to %v via %v: %v", sn, attrs.PublicIP, err)
			// }
		} else {
			log.Infof("removing subnet: %s PublicIP: %s VtepMAC: %s", sn, attrs.PublicIP, net.HardwareAddr(vxlanAttrs.VtepMAC))

			// Try to remove all entries - don't bail out if one of them fails.
			if err := nw.dev.DelARP(neighbor{IP: ip.FromIP(gw), MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
				log.Error("DelARP failed: ", err)
			}

			if err := nw.dev.DelFDB(neighbor{IP: neighborPublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
				log.Error("DelFDB failed: ", err)
			}

			if err := netlink.RouteDel(&vxlanRoute); err != nil {
				log.Errorf("failed to delete vxlanRoute (%s -> %s): %v", vxlanRoute.Dst, vxlanRoute.Gw, err)
			}
		}
	default:
		log.Error("internal error: unknown event type: ", e.Type)
	}
}
