obj-$(CONFIG_INFINIBAND_SDP) += ib_sdp.o
obj-$(CONFIG_INFINIBAND_SDP_DUMMY) += ib_sdp.o

ifeq ($(CONFIG_INFINIBAND_SDP_DUMMY),m)
ib_sdp-y := ib_sdp_dummy.o
else
ib_sdp-y := sdp_main.o sdp_cma.o sdp_bcopy.o sdp_proc.o sdp_tx.o sdp_rx.o sdp_zcopy.o
endif
