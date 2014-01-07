cpylmnl memo
============

SIGSEGV
-------

I do not check validation of len field --- nlmsghdr.nlmsg_len, nlattr.nla_len,
this causes SIGSEGV (MemoryError). you have to pay attention to it. e.g

    nlh = cpylmnl.netlink.Nlmsghdr(bytearray(1024))
    nlh.len = 2048

then

    mb = nlh.marshal_binary()

or

    with cpylmnl.Socket() as nl
        ...
        nl.send_nlmsg(nlh)

will read invalid address. functions which uses len field are:

- socket_send_nlmsg(), Socket.send_nlmsg()
- attr_get_payload_v(), Attribute.get_payload_v()
- Header.fprint()
- <class>.marshal_binary()
- <class>.marshal_bytes()


overwrap class
--------------

* Attribute wraps Nlattr which is struct nlattr in C.
* Header wraps Nlmsghdr which is struct nlmsghdr in C.
* NlmsgBatch pretends struct mnl_nlmsg_batch
* Socket pretends struct mnl_socket

functions for mnl_nlmsg_batch and mnl_socket handle struct itself as opaque.
see ``comparison'' below and py_class.py.


exception
---------

raises OSError() if errno (by ctypes.get_errno()) is not 0


underlay buffer
---------------

You have to keep buffer when creating new instance with put_header.
If you do not, like:

    nlh = cpylmnl.nlmsg_put_header(bytearray(4096))

will not work being expected. You have to:

    buf = bytearray(4096)
    nlh = cpylmnl.nlmsg_put_header(buf)
    ....
    cpylmnl.socket_sendto(buf[:nlh.len])

On the other hand

    nlh = cpylmn.netlink.Nlmsghdr(bytearray(4096))
    cpylmnl.socket_send_nlmsg(nlh)

will work properly. functions which retuns nlmsghdr, like constructor

* nlmsg_put_header(buffer)
  you have to keep buffer passed to, like above

* Nlmsghdr(bufsize), Header(bufsize)
  see above.

* put_new_header(bufsize)
  helper function for sending. allocate buffer and call put_header()


naming conversion
-----------------

Just removing mnl_ prefix. Raw C calls starts with c_ prefix.
e.g. mnl_nlmsg_put_header is

    import ctypes
    import cpylmnl as mnl

    nl1 = mnl.nlmsg_put_header(buf)
    p = mnl.c_nlmsg_put_header((ctypes.c_ubyte * len(buf)).from_buffer(buf))
    nl2 = p.contents

c_ functions returns raw value, on the other hand no c_ function returns
ctypes.pointer().contents as possible. 


return value
------------

note for functions which returns void *:

- add new functions appending to original name:
  - _v: return (c_ubyte * <appropriate len>)
  - _as: cast class specified in the param

    void *mnl_nlmsg_put_extra_header(struct nlmsghdr *nlh, size_t size)
    void *mnl_nlmsg_get_payload(const struct nlmsghdr *nlh)
    void *mnl_nlmsg_get_payload_offset(const struct nlmsghdr *nlh, size_t offset)
    void *mnl_attr_get_payload(const struct nlattr *attr)

- return c_ubyte array (c_ubyte * <appropriate len>)
  void *mnl_nlmsg_batch_head(struct mnl_nlmsg_batch *b)

- do nothing, return raw value
  void *mnl_nlmsg_get_payload_tail(const struct nlmsghdr *nlh)
  void *mnl_nlmsg_batch_current(struct mnl_nlmsg_batch *b)

I have not met the case using get_payload_tail. Writing about batch_current, you
can pass return value to raw c_ function like:

    import cpylmnl as mnl
    b = mnl.batch_start(bytearray(4096), 4096 * 2)
    try:
        nlh = mnl.nlmsg_put_header(mnl.c_batch_current(b))
        ...
    finally:
        mnl.batch_stop(b) # do not forget

To alleviate these, I added NlmsgBatch class

    with mnl.NlmsgBatch(4096, 4096 * 2) as b:
        nlh = mnl.nlmsg_put_header(b.current())

vebose?
