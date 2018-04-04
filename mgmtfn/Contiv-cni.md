## contiv创建虚拟网卡流程

[cni-plugin驱动](https://github.com/xxbandy/netplugin/blob/master/mgmtfn/k8splugin/driver.go)

### 创建ep的逻辑(()epID= 
```

    // 构建一个endpoint的请求\
    // netmaster/master/api.go
    /*
       //master.CreateEndpointRequest结果体
       type CreateEndpointRequest struct {
        TenantName   string          // tenant name
        NetworkName  string          // network name
        ServiceName  string          // service name
        EndpointID   string          // Unique identifier for the endpoint
        EPCommonName string          // Common name for the endpoint
        ConfigEP     intent.ConfigEP // Endpoint configuration
       }
    */

    mreq := master.CreateEndpointRequest{
        TenantName:   req.Tenant,
        NetworkName:  req.Network,
        ServiceName:  req.Group,
        EndpointID:   req.EndpointID, //pause容器id
        EPCommonName: req.Name,
        ConfigEP: intent.ConfigEP{
            Container:   req.EndpointID,
            Host:        pluginHost,
            ServiceName: req.Group,
        },
    }

    /*
    "github.com/contiv/netplugin/netmaster/mastercfg"
type CfgEndpointState struct {
    core.CommonState
    NetID            string            `json:"netID"`
    EndpointID       string            `json:"endpointID"`
    ServiceName      string            `json:"serviceName"`
    EndpointGroupID  int               `json:"endpointGroupId"`
    EndpointGroupKey string            `json:"endpointGroupKey"`
    IPAddress        string            `json:"ipAddress"`
    IPv6Address      string            `json:"ipv6Address"`
    MacAddress       string            `json:"macAddress"`
    HomingHost       string            `json:"homingHost"`
    IntfName         string            `json:"intfName"`
    VtepIP           string            `json:"vtepIP"`
    Labels           map[string]string `json:"labels"`
    ContainerID      string            `json:"containerId"`
    EPCommonName     string            `json:"epCommonName"`
}

"github.com/contiv/netplugin/cluster/cluster.go"

// masterReq 给master节点构造一个post/delete请求，用来实际创建endpoint
####### 核心代码
func masterReq(path string, req interface{}, resp interface{}, isDel bool) error {
    const retryCount = 3

    reqType := "POST"
    if isDel {
        reqType = "DELETE"
    }
    // first find the holder of master lock
    masterNode, err := getMasterLockHolder()
    if err == nil {
        url := "http://" + masterNode + path
        log.Infof("Making REST request to url: %s", url)

        // Make the REST call to master
        for i := 0; i < retryCount; i++ {

            if isDel {
                err = utils.HTTPDel(url)
            } else {
                err = utils.HTTPPost(url, req, resp)
            }
            if err != nil && strings.Contains(err.Error(), "connection refused") {
                log.Warnf("Error making POST request. Retrying...: Err: %v", err)
                // Wait a little before retrying
                time.Sleep(time.Second)
                continue
            } else if err != nil {
                log.Errorf("Error making %s request: Err: %v", reqType, err)
                return err
            }

            return err
        }

        return err
    }

    // Walk all netmasters and see if any of them respond
    for _, master := range MasterDB {
        masterPort := strconv.Itoa(master.Port)
        url := "http://" + master.HostAddr + ":" + masterPort + path

        log.Infof("Making REST request to url: %s", url)

        if isDel {
            err = utils.HTTPDel(url)
        } else {
            err = utils.HTTPPost(url, req, resp)
        }
        if err != nil {
            log.Warnf("Error making %s request: Err: %v", reqType, err)
            // continue and try making POST call to next master
        } else {
            return nil
        }
    }

    log.Errorf("error making %s request. all masters failed", reqType)
    return fmt.Errorf("the %s request failed", reqType)
}


func MasterPostReq(path string, req interface{}, resp interface{}) error {
    return masterReq(path, req, resp, false)
}
    */
    type CreateEndpointResponse struct {
        EndpointConfig mastercfg.CfgEndpointState // mastercfg.endpointstate.go
    }


    */
    var mresp master.CreateEndpointResponse
    //发送给master请求来创建endpoint,如果失败则清理网路，保证
    err = cluster.MasterPostReq("/plugin/createEndpoint", &mreq, &mresp)
    if err != nil {
        epCleanUp(req)
        return nil, err
    }
```