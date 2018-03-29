/***
Copyright 2016 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8splugin

//封装了netmaster的相关接口，用来直接对接contiv本身网络的驱动
//核心点在于github.com/contiv/netplugin/netmaster/intent
// github.com/contiv/netplugin/netmaster/master
// github.com/contiv/netplugin/netplugin/cluster
// github.com/vishvananda/netlink
// github.com/contiv/netplugin/utils
// github.com/contiv/netplugin/utils/netutils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	osexec "os/exec"
	"strconv" //数字转字符
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/netplugin/mgmtfn/k8splugin/cniapi"
	"github.com/contiv/netplugin/netmaster/intent"
	"github.com/contiv/netplugin/netmaster/master"
	"github.com/contiv/netplugin/netplugin/cluster"
	"github.com/contiv/netplugin/utils"
	"github.com/contiv/netplugin/utils/netutils"
	"github.com/vishvananda/netlink"
)

// epSpec contains the spec of the Endpoint to be created
// epSpec 包含了已经创建的endpoint的一些规范，比如租户，网络，分组，endpoint的id以及name等相关信息
type epSpec struct {
	Tenant     string `json:"tenant,omitempty"`
	Network    string `json:"network,omitempty"`
	Group      string `json:"group,omitempty"`
	EndpointID string `json:"endpointid,omitempty"`
	Name       string `json:"name,omitempty"`
}

// epAttr contains the assigned attributes of the created ep
// epAttr 包含一些给已经创建的endpoint的分配属性，主要是网络相关，比如ip地址，PortName(确定不是pod？)，网关以及ipv6地址和网关

type epAttr struct {
	IPAddress   string
	PortName    string
	Gateway     string
	IPv6Address string
	IPv6Gateway string
}

// epCleanUp deletes the ep from netplugin and netmaster
// epCleanUp 从netplugin和netmaster中删除一个endpoint
func epCleanUp(req *epSpec) error {
	// first delete from netplugin
	// ignore any errors as this is best effort
	// 从netplugin第一次删除 忽略任何错误
	//构造一个netID, network+tenant
	//
	//Tenant   Network       Nw Type  Encap type  Packet tag  Subnet                         Gateway        IPv6Subnet  IPv6Gateway  Cfgd Tag
	//------   -------       -------  ----------  ----------  -------                        ------         ----------  -----------  ---------
	//default  k8s-data-net  data     vlan        110         10.241.20.16-10.241.20.240/24  10.241.20.254
	//
	//

	//netID := k8s-data-net.default
	netID := req.Network + "." + req.Tenant

	// netPlugin.DeleteEndpoint("k8s-data-net.default-"+endpointID)
	// 疑问：这个函数是从哪里继承进来(netPlugin.DeleteEndpoint)

	pluginErr := netPlugin.DeleteEndpoint(netID + "-" + req.EndpointID)

	// now delete from master
	// 从master中删除
	//github.com/contiv/netplugin/netmaster/master/api.go
	//type DeleteEndpointRequest struct {
	//	TenantName  string // tenant name
	//	NetworkName string // network name
	//  ServiceName string // service name
	//  EndpointID  string // Unique identifier for the endpoint
	//  IPv4Address string // Allocated IPv4 address for the endpoint
	//	}

	//定义一个删除endpoint的请求数据
	delReq := master.DeleteEndpointRequest{
		TenantName:  req.Tenant,
		NetworkName: req.Network,
		ServiceName: req.Group,
		EndpointID:  req.EndpointID,
	}

	//定义一个从contiv删除ep的响应数据
	//type DeleteEndpointResponse struct {
	//	EndpointConfig mastercfg.CfgEndpointState // Endpoint config
	//	}
	var delResp master.DeleteEndpointResponse

	// 源码文件https://github.com/contiv/netplugin/blob/master/netplugin/cluster/cluster.go
	// MasterPostReq 像master节点构造一个post请求
	//func MasterPostReq(path string, req interface{}, resp interface{}) error {
	//	return masterReq(path, req, resp, false)
	//}

	//func MasterPostReq(path string, req interface{}, resp interface{})
	masterErr := cluster.MasterPostReq("/plugin/deleteEndpoint", &delReq, &delResp)

	if pluginErr != nil {
		log.Errorf("failed to delete endpoint: %s from netplugin %s",
			netID+"-"+req.EndpointID, pluginErr)
		return pluginErr
	}

	if masterErr != nil {
		log.Errorf("failed to delete endpoint %+v from netmaster, %s", delReq, masterErr)
	}

	return masterErr
}

// createEP 在contiv内部创建指定的Endpoint 并获取相关的网络信息，比如ip,mask,gw等
func createEP(req *epSpec) (*epAttr, error) {

	// 如果ep存在，抛出一个错误(网路号+.+租户号码)
	netID := req.Network + "." + req.Tenant
	ep, err := utils.GetEndpoint(netID + "-" + req.EndpointID)
	if err == nil {
		return nil, fmt.Errorf("the EP %s already exists", req.EndpointID)
	}

	// 构建一个endpoint的请求
	mreq := master.CreateEndpointRequest{
		TenantName:   req.Tenant,
		NetworkName:  req.Network,
		ServiceName:  req.Group,
		EndpointID:   req.EndpointID,
		EPCommonName: req.Name,
		ConfigEP: intent.ConfigEP{
			Container:   req.EndpointID,
			Host:        pluginHost,
			ServiceName: req.Group,
		},
	}

	var mresp master.CreateEndpointResponse
	//发送给master请求来创建endpoint,如果失败则清理网路，保证
	err = cluster.MasterPostReq("/plugin/createEndpoint", &mreq, &mresp)
	if err != nil {
		epCleanUp(req)
		return nil, err
	}

	// this response should contain IPv6 if the underlying network is configured with IPv6
	log.Infof("Got endpoint create resp from master: %+v", mresp)

	// Ask netplugin to create the endpoint
	//告知netplugin去创建endpoint(master和plugin同时创建是为了一致性对比？)
	err = netPlugin.CreateEndpoint(netID + "-" + req.EndpointID)
	if err != nil {
		log.Errorf("Endpoint creation failed. Error: %s", err)
		epCleanUp(req)
		return nil, err
	}

	//获取创建好的endpoint
	ep, err = utils.GetEndpoint(netID + "-" + req.EndpointID)
	if err != nil {
		epCleanUp(req)
		return nil, err
	}

	log.Debug(ep)
	// need to get the subnetlen from nw state.
	//从nw状态中获取子网长度subnetlen
	nw, err := utils.GetNetwork(netID)
	if err != nil {
		epCleanUp(req)
		return nil, err
	}

	epResponse := epAttr{}
	//port，ip，wg等香菇眼信息的赋值
	epResponse.PortName = ep.PortName
	epResponse.IPAddress = ep.IPAddress + "/" + strconv.Itoa(int(nw.SubnetLen))
	epResponse.Gateway = nw.Gateway

	if ep.IPv6Address != "" {
		epResponse.IPv6Address = ep.IPv6Address + "/" + strconv.Itoa(int(nw.IPv6SubnetLen))
		epResponse.IPv6Gateway = nw.IPv6Gateway
	}

	return &epResponse, nil
}

// getLink is a wrapper that fetches the netlink corresponding to the ifname
// getLink用来接收获取netlink，等同于ifname
/*
vishvananda/netlink/link.go
返回接口地址
type Link interface {
	Attrs() *LinkAttrs
	Type() string
}


type LinkAttrs struct {
	Index        int
	MTU          int
	TxQLen       int // Transmit Queue Length
	Name         string
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
	RawFlags     uint32
	ParentIndex  int         // index of the parent link device
	MasterIndex  int         // must be the index of a bridge
	Namespace    interface{} // nil | NsPid | NsFd
	Alias        string
	Statistics   *LinkStatistics
	Promisc      int
	Xdp          *LinkXdp
	EncapType    string
	Protinfo     *Protinfo
	OperState    LinkOperState
	NetNsID      int
	NumTxQueues  int
	NumRxQueues  int
}
*/

func getLink(ifname string) (netlink.Link, error) {
	// 查找一个link
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		if !strings.Contains(err.Error(), "Link not found") {
			log.Errorf("unable to find link %q. Error: %q", ifname, err)
			return link, err
		}
		// try once more as sometimes (somehow) link creation is taking
		// sometime, causing link not found error
		// 尝试等待一分钟，再次进行获取避免再次查找后仍然无法找到link
		time.Sleep(1 * time.Second)
		link, err = netlink.LinkByName(ifname)
		if err != nil {
			log.Errorf("unable to find link %q. Error %q", ifname, err)
		}
		return link, err
	}
	return link, err
}

// nsToPID 是一个从netns中提取PID的工具
// ns="/proc/35938/ns/net" 提取pid的过程
func nsToPID(ns string) (int, error) {
	// Make sure ns is well formed
	// 确定ns是一个可用的状态
	ok := strings.HasPrefix(ns, "/proc/")
	if !ok {
		return -1, fmt.Errorf("invalid nw name space: %v", ns)
	}

	elements := strings.Split(ns, "/")
	return strconv.Atoi(elements[2])
}

//将pid移植到NS中
func moveToNS(pid int, ifname string) error {
	// 查找一个link
	link, err := getLink(ifname)
	if err != nil {
		log.Errorf("unable to find link %q. Error %q", ifname, err)
		return err
	}

	// 将pid移动到期望的ns
	/*
		等同于 `ip link set $link netns $pid`
		func LinkSetNsPid(link Link, nspid int) error {
		return pkgHandle.LinkSetNsPid(link, nspid)
		}

	*/
	err = netlink.LinkSetNsPid(link, pid)
	if err != nil {
		log.Errorf("unable to move interface %s to pid %d. Error: %s",
			ifname, pid, err)
		return err
	}

	return nil
}

// setIfAttrs sets the required attributes for the container interface
// setIfAttrs 为容器设定一些相关的网络信息
func setIfAttrs(pid int, ifname, cidr, cidr6, newname string) error {
	//查看nsenter的绝对路径
	//nsenter是用一个ns中的其他进程来运行一个程序
	nsenterPath, err := osexec.LookPath("nsenter")
	if err != nil {
		return err
	}
	//获取ip的二进制程序绝对路径
	ipPath, err := osexec.LookPath("ip")
	if err != nil {
		return err
	}

	// 获取link相关信息，主要是网卡相关信息
	link, err := getLink(ifname)
	if err != nil {
		log.Errorf("unable to find link %q. Error %q", ifname, err)
		return err
	}

	// 移动到期望的ns里面
	/*
		//将网卡设备link放入一个新的netns,pid必须是一个运行的进程，等同于"ip link set $link netns $pid"
		func LinkSetNsPid(link Link, nspid int) error {
			return pkgHandle.LinkSetNsPid(link, nspid)
		}

		// LinkSetNsPid puts the device into a new network namespace. The
		// pid must be a pid of a running process.
		// Equivalent to: `ip link set $link netns $pid`
		func (h *Handle) LinkSetNsPid(link Link, nspid int) error {
			base := link.Attrs()
			h.ensureIndex(base)
			req := h.newNetlinkRequest(syscall.RTM_SETLINK, syscall.NLM_F_ACK)

			msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
			msg.Index = int32(base.Index)
			req.AddData(msg)

			b := make([]byte, 4)
			native.PutUint32(b, uint32(nspid))

			data := nl.NewRtAttr(syscall.IFLA_NET_NS_PID, b)
			req.AddData(data)

			_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
			return err
		}

	*/
	//将网卡设备link放入一个新的netns,pid必须是一个运行的进程，等同于"ip link set $link netns $pid"
	err = netlink.LinkSetNsPid(link, pid)
	if err != nil {
		log.Errorf("unable to move interface %s to pid %d. Error: %s",
			ifname, pid, err)
		return err
	}

	// 重新命名为一个新的ifname
	// nsenter -t $PID -n -F -- /sbin/ip link set dev docker0 name jdf@docker0
	nsPid := fmt.Sprintf("%d", pid) //数字转字符
	//os/exec
	//func (c *Cmd) CombinedOutput() ([]byte, error)
	rename, err := osexec.Command(nsenterPath, "-t", nsPid, "-n", "-F", "--", ipPath, "link",
		"set", "dev", ifname, "name", newname).CombinedOutput()
	if err != nil {
		log.Errorf("unable to rename interface %s to %s. Error: %s",
			ifname, newname, err)
		return nil
	}
	log.Infof("Output from rename: %v", rename)

	// 分配ip地址
	// nsenter -t $pid -n -F -- /sbin/ip address add cidr dev jdf@docker0
	assignIP, err := osexec.Command(nsenterPath, "-t", nsPid, "-n", "-F", "--", ipPath,
		"address", "add", cidr, "dev", newname).CombinedOutput()

	if err != nil {
		log.Errorf("unable to assign ip %s to %s. Error: %s",
			cidr, newname, err)
		return nil
	}
	log.Infof("Output from ip assign: %v", assignIP)

	//设置ipv6地址
	if cidr6 != "" {
		out, err := osexec.Command(nsenterPath, "-t", nsPid, "-n", "-F", "--", ipPath,
			"-6", "address", "add", cidr6, "dev", newname).CombinedOutput()
		if err != nil {
			log.Errorf("unable to assign IPv6 %s to %s. Error: %s",
				cidr6, newname, err)
			return nil
		}
		log.Infof("Output of IPv6 assign: %v", out)
	}

	// 将网卡启动
	// set，mark the device up
	// nsenter -t $pid -n -F -- /sbin/ip link set dev jdf@docker0 up
	bringUp, err := osexec.Command(nsenterPath, "-t", nsPid, "-n", "-F", "--", ipPath,
		"link", "set", "dev", newname, "up").CombinedOutput()

	if err != nil {
		log.Errorf("unable to assign ip %s to %s. Error: %s",
			cidr, newname, err)
		return nil
	}
	log.Debugf("Output from ip assign: %v", bringUp)
	return nil

}

//添加静态路由
func addStaticRoute(pid int, subnet, intfName string) error {
	nsenterPath, err := osexec.LookPath("nsenter")
	if err != nil {
		return err
	}

	ipPath, err := osexec.LookPath("ip")
	if err != nil {
		return err
	}

	nsPid := fmt.Sprintf("%d", pid)
	//等同于nnsenter -t $pid -n -F -- /sbin/ip route add subnet dev jdf@docker0
	_, err = osexec.Command(nsenterPath, "-t", nsPid, "-n", "-F", "--", ipPath,
		"route", "add", subnet, "dev", intfName).CombinedOutput()

	if err != nil {
		log.Errorf("unable to add route %s via %s. Error: %s",
			subnet, intfName, err)
		return err
	}

	return nil
}

// setDefGw 为容器的namespace设置默认网关
func setDefGw(pid int, gw, gw6, intfName string) error {
	nsenterPath, err := osexec.LookPath("nsenter")
	if err != nil {
		return err
	}
	routePath, err := osexec.LookPath("route")
	if err != nil {
		return err
	}
	// 设置默认网关
	nsPid := fmt.Sprintf("%d", pid)
	//等同于 nsenter -t $pid -n -F -- /sbin/route add default gw gateway jdf@docker
	out, err := osexec.Command(nsenterPath, "-t", nsPid, "-n", "-F", "--", routePath, "add",
		"default", "gw", gw, intfName).CombinedOutput()
	if err != nil {
		log.Errorf("unable to set default gw %s. Error: %s - %s", gw, err, out)
		return nil
	}

	//设置IPV6的网关
	if gw6 != "" {
		out, err := osexec.Command(nsenterPath, "-t", nsPid, "-n", "-F", "--", routePath,
			"-6", "add", "default", "gw", gw6, intfName).CombinedOutput()
		if err != nil {
			log.Errorf("unable to set default IPv6 gateway %s. Error: %s - %s", gw6, err, out)
			return nil
		}
	}

	return nil
}

// getEPSpec 使用pod的属性信息获取EP的相关信息
func getEPSpec(pInfo *cniapi.CNIPodAttr) (*epSpec, error) {
	resp := epSpec{}

	// 从kubeapi server获取相关的label
	epg, err := kubeAPIClient.GetPodLabel(pInfo.K8sNameSpace, pInfo.Name,
		"io.contiv.net-group")
	if err != nil {
		log.Errorf("Error getting epg. Err: %v", err)
		return &resp, err
	}

	// Safe to ignore the error return for subsequent invocations of GetPodLabel
	// 安全的忽略随后的GetPodLabel的调用
	netw, _ := kubeAPIClient.GetPodLabel(pInfo.K8sNameSpace, pInfo.Name,
		"io.contiv.network")
	tenant, _ := kubeAPIClient.GetPodLabel(pInfo.K8sNameSpace, pInfo.Name,
		"io.contiv.tenant")
	log.Infof("labels is %s/%s/%s for pod %s\n", tenant, netw, epg, pInfo.Name)
	resp.Tenant = tenant
	resp.Network = netw
	resp.Group = epg
	resp.EndpointID = pInfo.InfraContainerID
	resp.Name = pInfo.Name

	return &resp, nil
}

func setErrorResp(resp *cniapi.RspAddPod, msg string, err error) {
	resp.Result = 1
	resp.ErrMsg = msg
	resp.ErrInfo = fmt.Sprintf("Err: %v", err)
}

// addPod 是一个pod相关的handler
func addPod(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {

	resp := cniapi.RspAddPod{}

	logEvent("add pod")

	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Failed to read request: %v", err)
		return resp, err
	}

	pInfo := cniapi.CNIPodAttr{}
	if err := json.Unmarshal(content, &pInfo); err != nil {
		return resp, err
	}

	// 从kube api server获取labels
	epReq, err := getEPSpec(&pInfo)
	if err != nil {
		log.Errorf("Error getting labels. Err: %v", err)
		setErrorResp(&resp, "Error getting labels", err)
		return resp, err
	}

	ep, err := createEP(epReq)
	if err != nil {
		log.Errorf("Error creating ep. Err: %v", err)
		setErrorResp(&resp, "Error creating EP", err)
		return resp, err
	}

	var epErr error

	defer func() {
		if epErr != nil {
			log.Errorf("error %s, remove endpoint", epErr)
			netPlugin.DeleteHostAccPort(epReq.EndpointID)
			epCleanUp(epReq)
		}
	}()

	// 从netns获取pid(需要netlink)
	//这里的netns是pause容器的netns(/proc/35938/ns/net)

	pid, epErr := nsToPID(pInfo.NwNameSpace)
	if epErr != nil {
		log.Errorf("Error moving to netns. Err: %v", epErr)
		setErrorResp(&resp, "Error moving to netns", epErr)
		return resp, epErr
	}

	// Set interface attributes for the new port
	// 为新的port设置接口属性(基本上就是创建虚拟的网卡，设置ip等相关相信)
	// func setIfAttrs(pid int, ifname, cidr, cidr6, newname string) error
	epErr = setIfAttrs(pid, ep.PortName, ep.IPAddress, ep.IPv6Address, pInfo.IntfName)
	if epErr != nil {
		log.Errorf("Error setting interface attributes. Err: %v", epErr)
		setErrorResp(&resp, "Error setting interface attributes", epErr)
		return resp, epErr
	}

	//TODO: Host access needs to be enabled for IPv6
	// if Gateway is not specified on the nw, use the host gateway
	gwIntf := pInfo.IntfName
	gw := ep.Gateway
	if gw == "" {
		hostIf := netutils.GetHostIntfName(ep.PortName)
		hostIP, err := netPlugin.CreateHostAccPort(hostIf, ep.IPAddress)
		if err != nil {
			log.Errorf("Error setting host access. Err: %v", err)
		} else {
			err = setIfAttrs(pid, hostIf, hostIP, "", "host1")
			if err != nil {
				log.Errorf("Move to pid %d failed", pid)
			} else {
				gw, err = netutils.HostIPToGateway(hostIP)
				if err != nil {
					log.Errorf("Error getting host GW ip: %s, err: %v", hostIP, err)
				} else {
					gwIntf = "host1"
					// make sure service subnet points to eth0
					svcSubnet := contivK8Config.SvcSubnet
					addStaticRoute(pid, svcSubnet, pInfo.IntfName)
				}
			}
		}

	}

	// 设置默认网关
	epErr = setDefGw(pid, gw, ep.IPv6Gateway, gwIntf)
	if epErr != nil {
		log.Errorf("Error setting default gateway. Err: %v", epErr)
		setErrorResp(&resp, "Error setting default gateway", epErr)
		return resp, epErr
	}

	resp.Result = 0
	resp.IPAddress = ep.IPAddress

	if ep.IPv6Address != "" {
		resp.IPv6Address = ep.IPv6Address
	}

	resp.EndpointID = pInfo.InfraContainerID

	return resp, nil
}

// deletePod 删除pod的heandler
func deletePod(w http.ResponseWriter, r *http.Request, vars map[string]string) (interface{}, error) {

	resp := cniapi.RspAddPod{}

	logEvent("del pod")

	content, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Failed to read request: %v", err)
		return resp, err
	}

	pInfo := cniapi.CNIPodAttr{}
	if err := json.Unmarshal(content, &pInfo); err != nil {
		return resp, err
	}

	// Get labels from the kube api server
	epReq, err := getEPSpec(&pInfo)
	if err != nil {
		log.Errorf("Error getting labels. Err: %v", err)
		setErrorResp(&resp, "Error getting labels", err)
		return resp, err
	}

	netPlugin.DeleteHostAccPort(epReq.EndpointID)
	if err = epCleanUp(epReq); err != nil {
		log.Errorf("failed to delete pod, error: %s", err)
	}
	resp.Result = 0
	resp.EndpointID = pInfo.InfraContainerID
	return resp, nil
}
