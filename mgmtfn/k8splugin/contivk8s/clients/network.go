/***
Copyright 2015 Cisco Systems Inc. All rights reserved.

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

//定义一些网络操作相关的接口，这些接口会根据cniapi中的api.go中定义的CNI规范进行操作
//核心定义了AddPod和DelPod接口,通过定义的相关接口http://localhost/ContivCNI.AddPod 和http://localhost/ContivCNI.DelPod 进行contiv网络的添加和删除

package clients

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	log "github.com/Sirupsen/logrus"
	//封装CNI的API，定义了几个CNI的接口规范
	"github.com/contiv/netplugin/mgmtfn/k8splugin/cniapi"
)

//定义一个nw的url，应该是去读取本地contivk8s的socket
const (
	nwURL = "http://localhost"
)

// NWClient defines informatio needed for the k8s api client
// NWClient 定义了一些k8s api客户端操作的必要信息
// 相当于主要提供了两个接口NWClient.AddPod(podInfo) 和 NWClient.DelPod(podInfo)两个方法

type NWClient struct {
	baseURL string
	client  *http.Client //一个封装了Transport CheckRedirect  Jar  Timeout 的结构体
}

//创建一个socket连接
func unixDial(proto, addr string) (conn net.Conn, err error) {
	sock := cniapi.ContivCniSocket
	return net.Dial("unix", sock)
}

// NewNWClient creates an instance of the network driver client
// NewNWClient方法用来创建一个网络驱动的客户端接口(该接口应该可以直接调用一些相关的http方法)
func NewNWClient() *NWClient {
	//创建一个socket的结构体对象
	c := NWClient{}
	c.baseURL = nwURL

	//创建一个tcp连接(Transport本身是一个结构体)
	transport := &http.Transport{Dial: unixDial}
	//客户端使用创建的连接，返回一个http.Client类型的指针
	c.client = &http.Client{Transport: transport}

	return &c
}

// AddPod adds a pod to contiv using the cni api
// AddPod使用CNI API来追加一个pod到contiv网络中
//使用上述NWClient类型的方法
//需要传入一个interface类型的podinfo

//NWclient中的属性具有了AddPod方法，去操作网络相关的东西，同时返回cniapi包中api.go中定义的pod响应信息
func (c *NWClient) AddPod(podInfo interface{}) (*cniapi.RspAddPod, error) {
	//初始化网络添加响应信息结构体对象
	data := cniapi.RspAddPod{}
	//使用json.Marshal(v interface{}) 将podInfo信息转化成[]byte .json.Marshal是将接口转成json字符串,buf是一个[]byte类型的，需要使用string()进行转换
	buf, err := json.Marshal(podInfo)
	if err != nil {
		return nil, err
	}

	//podInfo的byte字符转换到buffer字节流中
	//func NewBuffer(buf []byte) *Buffer
	// type Buffer struct {} Buffer为一个空的结构体，同时赋予了该结构体很多的方法
	body := bytes.NewBuffer(buf)

	//构造添加pod的API接口  url http://localhost/ContivCNI.AddPod
	url := c.baseURL + cniapi.EPAddURL

	//给本地的API post一次请求(url:"http://localhost/ContivCNI.AddPod",contentType: "application/json",body:"buffer类型的Podinfo")
	//func (c *Client) Post(url string, contentType string, body io.Reader) (resp *Response, err error)
	r, err := c.client.Post(url, "application/json", body)
	if err != nil {
		return nil, err
	}
	//返回的r为一个*Response 类型的变量
	// 延迟关闭http请求，防止内存溢出
	defer r.Body.Close()

	switch {
	case r.StatusCode == int(404):
		return nil, fmt.Errorf("page not found")

	case r.StatusCode == int(403):
		return nil, fmt.Errorf("access denied")

	case r.StatusCode == int(500):
		//func ReadAll(r io.Reader) ([]byte, error)

		info, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		//[]byte 类型的info转换成data指向cniapi.RspAddPod{}类型的json字符串格式
		//func Unmarshal(data []byte, v interface{}) error
		err = json.Unmarshal(info, &data)
		if err != nil {
			return nil, err
		}
		return &data, fmt.Errorf("internal server error")

	case r.StatusCode != int(200):
		//如果增加网络操作执行成功，首先将请求的状态以及状态日志记录在日志中
		log.Errorf("POST Status '%s' status code %d \n", r.Status, r.StatusCode)
		return nil, fmt.Errorf("%s", r.Status)
	}

	//func ReadAll(r io.Reader) ([]byte, error)
	response, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(response, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

// DelPod deletes a pod from contiv using the cni api
// DelPod 使用cni api从contiv中删除一个pod

func (c *NWClient) DelPod(podInfo interface{}) error {
	//podInfo结构体转化成[]byte类型的buf
	buf, err := json.Marshal(podInfo)
	if err != nil {
		return err
	}

	//func NewBuffer(buf []byte) *Buffer
	// type Buffer struct {} Buffer为一个空的结构体，同时赋予了该结构体很多的方法
	// body是一个io.Reader类型的，因为是Buffer里面的操作
	body := bytes.NewBuffer(buf)
	//构造删除pod的url http://localhost/ContivCNI.DelPod
	url := c.baseURL + cniapi.EPDelURL
	//pod删除请求，并返回一个*Response
	r, err := c.client.Post(url, "application/json", body)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	//使用switch进行判断操作状态
	switch {
	case r.StatusCode == int(404):
		return fmt.Errorf("page not found")
	case r.StatusCode == int(403):
		return fmt.Errorf("access denied")
	case r.StatusCode != int(200):
		log.Errorf("GET Status '%s' status code %d \n", r.Status, r.StatusCode)
		return fmt.Errorf("%s", r.Status)
	}

	return nil
}
