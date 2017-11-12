obj-$(CONFIG_NVME_CORE)			+= nvme-core.o
obj-$(CONFIG_BLK_DEV_NVME)		+= nvme.o
obj-$(CONFIG_NVME_FABRICS)		+= nvme-fabrics.o
obj-$(CONFIG_NVME_RDMA)			+= nvme-rdma.o
obj-$(CONFIG_NVME_FC)			+= nvme-fc.o

obj-$(CONFIG_NVME_HOST_DUMMY)		+= nvme-rdma.o

# --with-nvmf-host-rdma-only
# dummy
obj-$(CONFIG_NVME_HOST_WITHOUT_FC)		+= nvme-fc.o

ifeq ($(CONFIG_NVME_HOST_DUMMY),m)
nvme-rdma-y				:= nvme-rdma_dummy.o
else
nvme-core-y				:= core.o
nvme-core-$(CONFIG_NVM)			+= lightnvm.o

nvme-y					+= pci.o

nvme-fabrics-y				+= fabrics.o

nvme-rdma-y				+= rdma.o

ifeq ($(CONFIG_NVME_HOST_WITHOUT_FC),m)
nvme-fc-y				+= nvme-fc_dummy.o
else
nvme-fc-y				+= fc.o
endif

endif
