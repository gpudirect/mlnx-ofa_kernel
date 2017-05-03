
obj-$(CONFIG_NVME_TARGET)		+= nvmet.o
obj-$(CONFIG_NVME_TARGET_LOOP)		+= nvme-loop.o
obj-$(CONFIG_NVME_TARGET_RDMA)		+= nvmet-rdma.o

obj-$(CONFIG_NVME_TARGET_DUMMY) += nvmet-rdma.o

ifeq ($(CONFIG_NVME_TARGET_DUMMY),m)
nvmet-rdma-y	+= nvmet-rdma_dummy.o
else
nvmet-y		+= core.o configfs.o admin-cmd.o io-cmd.o fabrics-cmd.o \
			discovery.o
nvme-loop-y	+= loop.o
nvmet-rdma-y	+= rdma.o
endif
