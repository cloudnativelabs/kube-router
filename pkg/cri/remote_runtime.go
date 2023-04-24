package cri

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"k8s.io/klog/v2"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	DefaultConnectionTimeout = 15 * time.Second
	maxMsgSize               = 1024 * 1024 * 16 // 16 MB
)

// remoteRuntimeService is a gRPC implementation of RuntimeService.
type remoteRuntimeService struct {
	timeout       time.Duration
	runtimeClient runtimeapi.RuntimeServiceClient
	conn          *grpc.ClientConn
}

type containerInfo struct {
	Pid int `json:"pid"`
}

// NewRemoteRuntimeService creates a new RuntimeService.
func NewRemoteRuntimeService(endpoint string, connectionTimeout time.Duration) (RuntimeService, error) {
	proto, addr, err := EndpointParser(endpoint)
	if err != nil {
		return nil, err
	}

	klog.V(4).Infof("[RuntimeService] got endpoint %s (proto=%s, path=%s)", endpoint, proto, addr)

	if proto != "unix" {
		return nil, errors.New("[RuntimeService] only unix socket is currently supported")
	}

	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)))
	if err != nil {
		klog.Errorf("Connect remote runtime %s failed: %v", addr, err)
		return nil, err
	}

	return &remoteRuntimeService{
		timeout:       connectionTimeout,
		runtimeClient: runtimeapi.NewRuntimeServiceClient(conn),
		conn:          conn,
	}, nil
}

// ContainerInfo returns verbose info of provided container.
func (r *remoteRuntimeService) ContainerInfo(id string) (*containerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	// Verbose should be set, otherwise we'll get an empty slice. see
	resp, err := r.runtimeClient.ContainerStatus(ctx, &runtimeapi.ContainerStatusRequest{
		ContainerId: id,
		Verbose:     true,
	})
	if err != nil {
		return nil, err
	}

	info := containerInfo{}

	if err := json.Unmarshal([]byte(resp.Info["info"]), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Close tears down the *grpc.ClientConn and all underlying connections.
func (r *remoteRuntimeService) Close() error {
	if err := r.conn.Close(); err != nil {
		return err
	}
	return nil
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", addr)
}

// EndpointParser returns protocol and path of provided endpoint
func EndpointParser(endpoint string) (proto string, path string, err error) {

	result := strings.Split(endpoint, "://")

	if len(result) < 2 {
		return "", "", errors.New("bad endpoint format. should be 'protocol://path'")
	}
	return result[0], result[1], nil
}
