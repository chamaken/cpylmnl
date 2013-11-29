#!/bin/sh

UAPI_SRCDIR=$HOME/gitr/linux/include/uapi
LIBMNL_SRCDIR=$HOME/gitr/netfilter/libmnl
LIBMNL_SO=/usr/local/lib/libmnl.so

counter_sources() {
cat <<EOF
# UAPI
# linux UAPI
$UAPI_SRCDIR/linux/netlink.h				ORIGINAL_C_SOURCE/linux/netlink.h
$UAPI_SRCDIR/linux/if_link.h				h/linux/if_link.h
$UAPI_SRCDIR/linux/rtnetlink.h				h/linux/rtnetlink.h
$UAPI_SRCDIR/linux/genetlink.h				h/linux/genetlink.h
$UAPI_SRCDIR/linux/if_addr.h				h/linux/if_addr.h
$UAPI_SRCDIR/linux/netfilter/nf_conntrack_common.h	h/linux/netfilter/nf_conntrack_common.h
$UAPI_SRCDIR/linux/netfilter/nf_conntrack_tcp.h		h/linux/netfilter/nf_conntrack_tcp.h
$UAPI_SRCDIR/linux/netfilter/nfnetlink.h		h/linux/netfilter/nfnetlink.h
$UAPI_SRCDIR/linux/netfilter/nfnetlink_compat.h		h/linux/netfilter/nfnetlink_compat.h
$UAPI_SRCDIR/linux/netfilter/nfnetlink_conntrack.h	h/linux/netfilter/nfnetlink_conntrack.h
$UAPI_SRCDIR/linux/netfilter/nfnetlink_log.h		h/linux/netfilter/nfnetlink_log.h
$UAPI_SRCDIR/linux/if.h					h/linux/if.h

# libmnl source
$LIBMNL_SRCDIR/include/libmnl/libmnl.h			ORIGINAL_C_SOURCE/mnl/libmnl.h
$LIBMNL_SRCDIR/src/attr.c				ORIGINAL_C_SOURCE/mnl/attr.c
$LIBMNL_SRCDIR/src/socket.c				ORIGINAL_C_SOURCE/mnl/socket.c
$LIBMNL_SRCDIR/src/nlmsg.c				ORIGINAL_C_SOURCE/mnl/nlmsg.c
$LIBMNL_SRCDIR/src/callback.c				ORIGINAL_C_SOURCE/mnl/callback.c

# libmnl examples
$LIBMNL_SRCDIR/examples/netfilter/nfct-dump.c		ORIGINAL_C_SOURCE/mnl/examples/netfilter/nfct-dump.c
$LIBMNL_SRCDIR/examples/netfilter/nfct-event.c		ORIGINAL_C_SOURCE/mnl/examples/netfilter/nfct-event.c
$LIBMNL_SRCDIR/examples/netfilter/nf-queue.c		ORIGINAL_C_SOURCE/mnl/examples/netfilter/nf-queue.c
$LIBMNL_SRCDIR/examples/netfilter/nf-log.c		ORIGINAL_C_SOURCE/mnl/examples/netfilter/nf-log.c
$LIBMNL_SRCDIR/examples/netfilter/nfct-daemon.c		ORIGINAL_C_SOURCE/mnl/examples/netfilter/nfct-daemon.c
$LIBMNL_SRCDIR/examples/netfilter/nfct-create-batch.c	ORIGINAL_C_SOURCE/mnl/examples/netfilter/nfct-create-batch.c
$LIBMNL_SRCDIR/examples/rtnl/rtnl-link-event.c		ORIGINAL_C_SOURCE/mnl/examples/rtnl/rtnl-link-event.c
$LIBMNL_SRCDIR/examples/rtnl/rtnl-addr-dump.c		ORIGINAL_C_SOURCE/mnl/examples/rtnl/rtnl-addr-dump.c
$LIBMNL_SRCDIR/examples/rtnl/rtnl-link-dump.c		ORIGINAL_C_SOURCE/mnl/examples/rtnl/rtnl-link-dump.c
$LIBMNL_SRCDIR/examples/rtnl/rtnl-route-add.c		ORIGINAL_C_SOURCE/mnl/examples/rtnl/rtnl-route-add.c
$LIBMNL_SRCDIR/examples/rtnl/rtnl-route-event.c		ORIGINAL_C_SOURCE/mnl/examples/rtnl/rtnl-route-event.c
$LIBMNL_SRCDIR/examples/rtnl/rtnl-link-dump2.c		ORIGINAL_C_SOURCE/mnl/examples/rtnl/rtnl-link-dump2.c
$LIBMNL_SRCDIR/examples/rtnl/rtnl-route-dump.c		ORIGINAL_C_SOURCE/mnl/examples/rtnl/rtnl-route-dump.c
$LIBMNL_SRCDIR/examples/rtnl/rtnl-link-set.c		ORIGINAL_C_SOURCE/mnl/examples/rtnl/rtnl-link-set.c
$LIBMNL_SRCDIR/examples/rtnl/rtnl-link-dump3.c		ORIGINAL_C_SOURCE/mnl/examples/rtnl/rtnl-link-dump3.c
$LIBMNL_SRCDIR/examples/kobject/kobject-event.c		ORIGINAL_C_SOURCE/mnl/examples/kobject/kobject-event.c
$LIBMNL_SRCDIR/examples/genl/genl-family-get.c		ORIGINAL_C_SOURCE/mnl/examples/genl/genl-family-get.c
$LIBMNL_SRCDIR/examples/genl/genl-group-events.c	ORIGINAL_C_SOURCE/mnl/examples/genl/genl-group-events.c
EOF
}


libmnl_symbols() {
    nm -D --defined-only $LIBMNL_SO | awk '$2=="T" {print $3}' | sed -e 's/^mnl_/'
}

# in bash, done < $t can be replace with
# <(counter_sources | grep -Ev "^[ 	]*(#|$)")
t=$(tempfile) # || exit
trap "rm -f -- '$t'" EXIT
counter_sources | grep -Ev "^[ 	]*(#|$)" > $t

ncsrc=0
while read line; do
    set -- $line
    diff -uw $1 $2
    ncsrc=$((ncsrc + 1))
done < $t

# cleanup tempfile 
rm -f -- "$t"
trap - EXIT

wcl=`find h -type f | wc -l`
if [ $wcl -ne $ncsrc ]; then
    echo "files in h: $wcl, but listed above: $ncsrc" 1>&2
fi


libmnl_symbols | while read s; do
    if ! grep $s cpylmnl/*.py > /dev/null; then
	echo "not defined: $s"
    fi
done
