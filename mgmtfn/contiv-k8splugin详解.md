### Contiv k8splugin

#### 目录结构

```
├── certs
│   ├── ca.crt
│   ├── contiv_certs.json
│   ├── contiv.json
│   ├── contiv_token.json
│   ├── kubecfg.crt
│   ├── kubecfg.key
│   ├── server.crt
│   └── server.key
├── cniapi
│   └── api.go
├── cniserver.go
├── contivk8s
│   ├── clients
│   ├── k8s_cni.go
│   └── k8s_cni_test.go
├── driver.go
├── driver_test.go
├── kubeClient.go
├── kubeClient_test.go
├── README.md
└── types.go

```


核心主程序：`contivk8s`

```
# tree -L 2 contivk8s/
contivk8s/
├── clients
│   └── network.go
├── k8s_cni.go
└── k8s_cni_test.go

```

CNI接口程序

```
# tree -L 2 cniapi/
cniapi/
└── api.go
```

辅助函数
```
├── cniserver.go
├── driver.go
├── driver_test.go
├── kubeClient.go
├── kubeClient_test.go
├── README.md
└── types.go
```


#### contivk8s核心程序

```
# tree -L 2 contivk8s/
contivk8s/
├── clients
│   └── network.go
├── k8s_cni.go
└── k8s_cni_test.go

```

