obj-$(CONFIG_SUNRPC_XPRT_RDMA_CLIENT) += xprtrdma.o
obj-$(CONFIG_SUNRPC_XPRT_RDMA_DUMMY) += xprtrdma.o svcrdma.o
obj-$(CONFIG_SUNRPC_XPRT_RDMA) += rpcrdma.o

rpcrdma-y := rpcrdma_dummy.o

ifeq ($(CONFIG_SUNRPC_XPRT_RDMA_DUMMY),m)
xprtrdma-y := xprtrdma_dummy.o
svcrdma-y := svcrdma_dummy.o
else
xprtrdma-y := transport.o rpc_rdma.o verbs.o

obj-$(CONFIG_SUNRPC_XPRT_RDMA_SERVER) += svcrdma.o

svcrdma-y := svc_rdma.o svc_rdma_transport.o \
	svc_rdma_marshal.o svc_rdma_sendto.o svc_rdma_recvfrom.o
endif
