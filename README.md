cpylmnl
========

Python wrapper of libmnl using ctypes, under heavy development

sample
------

see examples


installation
------------

not prepared yet


requires
--------

* libmnl
* Python >= 2.6
* test reqs (optional): python-coverage, python-nose


links
-----

* libmnl: http://netfilter.org/projects/libmnl/
* pymnl: http://pymnl.wikispot.org/


from C to Python
----------------

* "nlstruct.py" is helper for representing netlink structs by ctypes.
* symbols are defined in "\_libmnlh.py". 
* binding functions in "\_cproto.py".
* tweaking for Python in each "\_nlmsg.py", "\_attr.py", "\_socket.py", "\_callback.py"
* letting those be Python class in "\__init__.py"


comparison
----------

| original				| cpylmnl			| remarks			|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_attr_get_type			| Attr.get_type			|				|
| mnl_attr_get_len			| Attr.get_len			|				|
| mnl_attr_get_payload_len		| Attr.get_payload_len		|				|
| mnl_attr_get_payload			| Attr.get_payload		|				|
| (add)					| Attr.get_payload_v		| returns array of c_ubyte	|
| (add)					| Attr.get_payload_as		| cast specified class		|
| mnl_attr_ok				| Attr.ok			|				|
| mnl_attr_next				| Attr.next_attribute		| returns contents, not pointer	|
| mnl_attr_type_valid			| Attr.type_valid		|				|
| mnl_attr_validate			| Attr.validate			|				|
| mnl_attr_validate2			| Attr.validate2		|				|
| mnl_attr_parse			| Msghdr.parse			|				|
| mnl_attr_parse_nested			| Attr.parse_nested		|				|
| mnl_attr_parse_payload		| attr_parse_payload		|				|
| mnl_attr_get_u8			| Attr.get_u8			|				|
| mnl_attr_get_u16			| Attr.get_u16			|				|
| mnl_attr_get_u32			| Attr.get_u32			|				|
| mnl_attr_get_u64			| Attr.get_u64			|				|
| mnl_attr_get_str			| Attr.get_str			|				|
| mnl_attr_put				| Msghdr.put			| require ctypes data type	|
| mnl_attr_put_u8			| Msghdr.put_u8			|				|
| mnl_attr_put_u16			| Msghdr.put_u16		|				|
| mnl_attr_put_u32			| Msghdr.put_u32		|				|
| mnl_attr_put_u64			| Msghdr.put_u64		|				|
| mnl_attr_put_str			| Msghdr.putstr			|				|
| mnl_attr_put_strz			| Msghdr.putstrz		|				|
| mnl_attr_nest_start			| Msghdr.nest_start		| returns contents		|
| mnl_attr_put_check			| Msghdr.put_check		| require ctypes data type	|
| mnl_attr_put_u8_check			| Msghdr.put_u8_check		|				|
| mnl_attr_put_u16_check		| Msghdr.put_u16_check		|				|
| mnl_attr_put_u32_check		| Msghdr.put_u32_check		|				|
| mnl_attr_put_u64_check		| Msghdr.put_u64_check		|				|
| mnl_attr_put_str_check		| Msghdr.put_str_check		|				|
| mnl_attr_put_strz_check		| Msghdr.put_strz_check		|				|
| mnl_attr_nest_start_check		| Msghdr.nest_start_check	| returns contents		|
| mnl_attr_nest_end			| Msghdr.nest_end		|				|
| mnl_attr_nest_cancel			| Msghdr.nest_cancel		|				|
| mnl_attr_cb_t				| mnl_attr_cb_t			| attr cb decorator		|
| (add)					| attribute_cb			| receive Attribute		|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_nlmsg_size			| Msghdr.size			|				|
| mnl_nlmsg_get_payload_len		| Msghdr.get_payload_len	|				|
| mnl_nlmsg_put_header			| Msghdr.put_header		| buf must be mutable		|
| (add)					| put_new_header		| allocate and put header	|
| mnl_nlmsg_put_extra_header		| Msghdr.put_extra_header	| 				|
| (add)					| Msghdr.put_extra_header_v	| 				|
| (add)					| Msghdr.put_extra_header_as	| 				|
| mnl_nlmsg_get_paylod			| Msghdr.get_payload		|				|
| (add)					| Msghdr.get_payload_v		| returns array of c_ubyte	|
| (add)					| Msghdr.get_payload_as		| cast specified class		|
| mnl_nlmsg_get_payload_offset		| Msghdr.get_payload_offset	|				|
| (add)					| Msghdr.get_payload_offset_v	|				|
| (add)					| Msghdr.get_payload_offset_as	|				|
| mnl_nlmsg_ok				| Msghdr.ok			|				|
| mnl_nlmsg_next			| Msghdr.next_header		|				|
| mnl_nlmsg_get_payload_tail		| Msghdr.get_payload_tail	|				|
| mnl_nlmsg_seq_ok			| Msghdr.seq_ok			|				|
| mnl_nlmsg_portid_ok			| Msghdr.portid_ok		|				|
| mnl_nlmsg_fprintf			| Msghdr.fprint			| require file not descriptor	|
| mnl_nlmsg_batch_start			| NlmsgBatch			|				|
| mnl_nlmsg_batch_stop			| NlmsgBatch.stop		|				|
| mnl_nlmsg_batch_next			| NlmsgBatch.next_batch		|				|
| mnl_nlmsg_batch_reset			| NlmsgBatch.reset		|				|
| mnl_nlmsg_batch_size			| NlmsgBatch.size		|				|
| mnl_nlmsg_batch_head			| NlmsgBatch.head		|				|
| mnl_nlmsg_batch_current		| NlmsgBatch.current		|				|
| (add)					| NlmsgBatch.current_v		|				|
| mnl_nlmsg_batch_is_empty		| NlmsgBatch.is_empty		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_cb_run				| cb_run			| 				|
| mnl_cb_run2				| cb_run2			|				|
| mnl_cb_t				| mnl_cb_t			| cb decorator			|
| (add)					| header_cb			| receive Header		|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_socket_get_fd			| Socket.get_fd			|				|
| mnl_socket_get_portid			| Socket.get_portid		|				|
| mnl_socket_open			| Socket			| pass int as bus		|
| mnl_socket_fdopen			| Socket			| pass socket.socket as fd	|
| mnl_socket_bind			| Socket.bind			|				|
| mnl_socket_sendto			| Socket.sendto			| require mutable buffer	|
| (add)					| Socket.send_nlmsg		| pass nlmsghdr instead of buf	|
| mnl_socket_recvfrom			| Socket.recv_into		|				|
| (add)					| Socket.recv			| require buflen and returns	|
|					|				| mutable buffer not bytes	|
| mnl_socket_close			| Socket.close			|				|
| mnl_socket_setsockopt			| Socket.setsockopt		| require mutable buffer	|
| mnl_socket_getsockopt			| Socket.getsockopt		| require buflen, returns bytes	|
| (add)					| Socket.getsockopt_as		| 				|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_attr_for_each_nested		| Attr.nesteds			| reprerent by iterator		|
| mnl_attr_for_each			| Msghdr.attributes		|				|
| mnl_attr_for_each_payload		| payload_attributes		|				|
