UAPI_DIR := $(HOME)/gitr/linux/include/uapi
H_FILES := $(shell find -name \*.h)

%.h: $(UAPI_DIR)/linux/%.h
	cp -a $< $@

# I do not know a stem including dir /
netfilter/%.h: $(UAPI_DIR)/linux/netfilter/%.h
	cp -a $< $@

all: $(H_FILES)
