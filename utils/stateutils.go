package utils

import (
	"github.com/contiv/netplugin/drivers"
	"github.com/contiv/netplugin/netmaster/mastercfg"
)

// GetEndpoint is a utility that reads the EP oper state
// epID := k8s-data-net.default-$pausecontainerid
func GetEndpoint(epID string) (*drivers.OperEndpointState, error) {
	// Get hold of the state driver
	stateDriver, err := GetStateDriver()
	if err != nil {
		return nil, err
	}

	/*
	   type OperEndpointState struct {
	   	core.CommonState
	   	NetID       string `json:"netID"`
	   	EndpointID  string `json:"endpointID"`
	   	ServiceName string `json:"serviceName"`
	   	ContUUID    string `json:"contUUID"`
	   	IPAddress   string `json:"ipAddress"`
	   	IPv6Address string `json:"ipv6Address"`
	   	MacAddress  string `json:"macAddress"`
	   	HomingHost  string `json:"homingHost"`
	   	IntfName    string `json:"intfName"`
	   	PortName    string `json:"portName"`
	   	VtepIP      string `json:"vtepIP"`
	   }

	*/

	operEp := &drivers.OperEndpointState{}
	operEp.StateDriver = stateDriver
	err = operEp.Read(epID)
	if err != nil {
		return nil, err
	}

	return operEp, nil
}

// GetNetwork is a utility that reads the n/w oper state
func GetNetwork(networkID string) (*mastercfg.CfgNetworkState, error) {
	// Get hold of the state driver
	stateDriver, err := GetStateDriver()
	if err != nil {
		return nil, err
	}

	// find the network from network id
	nwCfg := &mastercfg.CfgNetworkState{}
	nwCfg.StateDriver = stateDriver
	err = nwCfg.Read(networkID)
	if err != nil {
		return nil, err
	}

	return nwCfg, nil
}
