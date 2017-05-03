ccflags-y		:= -Idrivers/target -Idrivers/target/iscsi
obj-$(CONFIG_INFINIBAND_ISERT)	+= ib_isert.o
obj-$(CONFIG_INFINIBAND_ISERT_DUMMY) += ib_isert.o

ifeq ($(CONFIG_INFINIBAND_ISERT_DUMMY),m)
ib_isert-y := ib_isert_dummy.o
endif
