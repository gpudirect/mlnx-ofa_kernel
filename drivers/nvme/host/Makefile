obj-$(CONFIG_NVME_CORE)			+= nvme-core.o
obj-$(CONFIG_BLK_DEV_NVME)		+= nvme.o
obj-$(CONFIG_NVME_FABRICS)		+= nvme-fabrics.o
obj-$(CONFIG_NVME_RDMA)			+= nvme-rdma.o

obj-$(CONFIG_NVME_HOST_DUMMY)		+= nvme-rdma.o

ifeq ($(CONFIG_NVME_HOST_DUMMY),m)
nvme-rdma-y				:= nvme-rdma_dummy.o
else
nvme-core-y				:= core.o
nvme-core-$(CONFIG_BLK_DEV_NVME_SCSI)	+= scsi.o
nvme-core-$(CONFIG_NVM)			+= lightnvm.o

nvme-y					+= pci.o

nvme-fabrics-y				+= fabrics.o

nvme-rdma-y				+= rdma.o
endif
