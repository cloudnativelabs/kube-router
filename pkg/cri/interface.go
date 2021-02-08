package cri

// RuntimeService is the client API for RuntimeService service.
type RuntimeService interface {
	ContainerInfo(id string) (*containerInfo, error)
	Close() error
}
