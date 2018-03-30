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

//定义了一些CNI的接口规范
package cniapi

// cni api definitions shared between the cni executable and netplugin

// PluginPath is the path to the listen socket directory for netplugin
// 定义netplugin监听socket的目录
const PluginPath = "/run/contiv"

// ContivCniSocket is the full path to the listen socket for netplugin
//定义ContivCNI 的socket文件
const ContivCniSocket = "/run/contiv/contiv-cni.sock"

// EPAddURL is the rest point for adding an endpoint
//定义了为pod增加一个endpoint的接口
const EPAddURL = "/ContivCNI.AddPod"

// EPDelURL is the rest point for deleting an endpoint
//定义了为pod删除一个endpoint的接口
const EPDelURL = "/ContivCNI.DelPod"

// CNIPodAttr holds attributes of the pod to be attached or detached
// CNIPodAttr定义了pod被添加网络和删除网络中的一些基本属性。该结构体最终转换成两个json字符串. 结构体中的omitempty 标签表示可以忽略该数据
type CNIPodAttr struct {
	Name             string `json:"K8S_POD_NAME,omitempty"`               // podname ->appname
	K8sNameSpace     string `json:"K8S_POD_NAMESPACE,omitempty"`          //k8s ns
	InfraContainerID string `json:"K8S_POD_INFRA_CONTAINER_ID,omitempty"` //pausecontainer id
	NwNameSpace      string `json:"CNI_NETNS,omitempty"`                  //net namespace
	IntfName         string `json:"CNI_IFNAME,omitempty"`                 //容器内部新的网卡设备名
}

// RspAddPod contains the response to the AddPod
// RspAddPod 包含一些响应信息
type RspAddPod struct {
	Result      uint   `json:"result,omitempty"`      //result
	EndpointID  string `json:"endpointid,omitempty"`  //endpoint id
	IPAddress   string `json:"ipaddress,omitempty"`   //ip v4
	IPv6Address string `json:"ipv6address,omitempty"` //ip v6
	ErrMsg      string `json:"errmsg,omitempty"`      //err msg
	ErrInfo     string `json:"errinfo,omitempty"`     //err info
}
