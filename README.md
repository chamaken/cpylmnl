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
| mnl_attr_get_type			| Attribute.get_type		|				|
| mnl_attr_get_len			| Attribute.get_len		|				|
| mnl_attr_get_payload_len		| Attribute.get_payload_len	|				|
| mnl_attr_get_payload			| Attribute.get_payload		|				|
| (add)					| Attribute.get_payload_v	| returns array of c_ubyte	|
| (add)					| Attribute.get_payload_as	| cast specified class		|
| mnl_attr_ok				| Attribute.ok			|				|
| mnl_attr_next				| Attribute.next_attribute	| returns contents, not pointer	|
| mnl_attr_type_valid			| Attribute.type_valid		|				|
| mnl_attr_validate			| Attribute.validate		|				|
| mnl_attr_validate2			| Attribute.validate2		|				|
| mnl_attr_parse			| Header.parse			|				|
| mnl_attr_parse_nested			| Attribute.parse_nested	|				|
| mnl_attr_parse_payload		| attr_parse_payload		|				|
| mnl_attr_get_u8			| Attribute.get_u8		|				|
| mnl_attr_get_u16			| Attribute.get_u16		|				|
| mnl_attr_get_u32			| Attribute.get_u32		|				|
| mnl_attr_get_u64			| Attribute.get_u64		|				|
| mnl_attr_get_str			| Attribute.get_str		|				|
| mnl_attr_put				| Header.put			| require ctypes data type	|
| mnl_attr_put_u8			| Header.put_u8			|				|
| mnl_attr_put_u16			| Header.put_u16		|				|
| mnl_attr_put_u32			| Header.put_u32		|				|
| mnl_attr_put_u64			| Header.put_u64		|				|
| mnl_attr_put_str			| Header.putstr			|				|
| mnl_attr_put_strz			| Header.putstrz		|				|
| mnl_attr_nest_start			| Header.nest_start		| returns contents		|
| mnl_attr_put_check			| Header.put_check		| require ctypes data type	|
| mnl_attr_put_u8_check			| Header.put_u8_check		|				|
| mnl_attr_put_u16_check		| Header.put_u16_check		|				|
| mnl_attr_put_u32_check		| Header.put_u32_check		|				|
| mnl_attr_put_u64_check		| Header.put_u64_check		|				|
| mnl_attr_put_str_check		| Header.put_str_check		|				|
| mnl_attr_put_strz_check		| Header.put_strz_check		|				|
| mnl_attr_nest_start_check		| Header.nest_start_check	| returns contents		|
| mnl_attr_nest_end			| Header.nest_end		|				|
| mnl_attr_nest_cancel			| Header.nest_cancel		|				|
| mnl_attr_cb_t				| mnl_attr_cb_t			| attr cb decorator		|
| (add)					| attribute_cb			| receive Attribute		|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_nlmsg_size			| Header.size			|				|
| mnl_nlmsg_get_payload_len		| Header.get_payload_len	|				|
| mnl_nlmsg_put_header			| Header.put_header		| buf must be mutable		|
| (add)					| put_new_header		| allocate and put header	|
| mnl_nlmsg_put_extra_header		| Header.put_extra_header	| 				|
| (add)					| Header.put_extra_header_v	| 				|
| (add)					| Header.put_extra_header_as	| 				|
| mnl_nlmsg_get_paylod			| Header.get_payload		|				|
| (add)					| Header.get_payload_v		| returns array of c_ubyte	|
| (add)					| Header.get_payload_as		| cast specified class		|
| mnl_nlmsg_get_payload_offset		| Header.get_payload_offset	|				|
| (add)					| Header.get_payload_offset_v	|				|
| (add)					| Header.get_payload_offset_as	|				|
| mnl_nlmsg_ok				| Header.ok			|				|
| mnl_nlmsg_next			| Header.next_header		|				|
| mnl_nlmsg_get_payload_tail		| Header.get_payload_tail	|				|
| mnl_nlmsg_seq_ok			| Header.seq_ok			|				|
| mnl_nlmsg_portid_ok			| Header.portid_ok		|				|
| mnl_nlmsg_fprintf			| Header.fprint			| require file not descriptor	|
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
| mnl_attr_for_each_nested		| Attribute.nesteds		| reprerent by iterator		|
| mnl_attr_for_each			| Header.attributes		|				|
| mnl_attr_for_each_payload		| payload_attributes		|				|
