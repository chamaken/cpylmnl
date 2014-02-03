cpylmnl
========

python wrapper of libmnl using ctypes, under heavy development

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
* test reqs (optional): **python-coverage**, **python-nose**


links
-----

* libmnl: http://netfilter.org/projects/libmnl/
* pymnl: http://pymnl.wikispot.org/


comparison
----------

| original				| cpylmnl			| remarks			|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_attr_get_type			| attr_get_type			|				|
| mnl_attr_get_len			| attr_get_len			|				|
| mnl_attr_get_payload_len		| attr_get_payload_len		|				|
| mnl_attr_get_payload			| attr_get_payload		|				|
| (add)					| attr_get_payload_v		| returns array of c_ubyte	|
| (add)					| attr_get_payload_as		| cast specified class		|
| mnl_attr_ok				| attr_ok			|				|
| mnl_attr_next				| attr_next			| returns contents, not pointer	|
| mnl_attr_type_valid			| attr_type_valid		|				|
| mnl_attr_validate			| attr_validate			|				|
| mnl_attr_validate2			| attr_validate2		|				|
| mnl_attr_parse			| attr_parse			|				|
| mnl_attr_parse_nested			| attr_parse_nested		|				|
| mnl_attr_parse_payload		| attr_parse_payload		|				|
| mnl_attr_get_u8			| attr_get_u8			|				|
| mnl_attr_get_u16			| attr_get_u16			|				|
| mnl_attr_get_u32			| attr_get_u32			|				|
| mnl_attr_get_u64			| attr_get_u64			|				|
| mnl_attr_get_str			| attr_get_str			|				|
| mnl_attr_put				| attr_put			| data must be mutable		|
| mnl_attr_put_u8			| attr_put_u8			|				|
| mnl_attr_put_u16			| attr_put_u16			|				|
| mnl_attr_put_u32			| attr_put_u32			|				|
| mnl_attr_put_u64			| attr_put_u64			|				|
| mnl_attr_put_str			| attr_putstr			|				|
| mnl_attr_put_strz			| attr_putstrz			|				|
| mnl_attr_nest_start			| attr_nest_start		| returns contents		|
| mnl_attr_put_check			| attr_put_check		| data must be mutable		|
| mnl_attr_put_u8_check			| attr_put_u8_check		|				|
| mnl_attr_put_u16_check		| attr_put_u16_check		|				|
| mnl_attr_put_u32_check		| attr_put_u32_check		|				|
| mnl_attr_put_u64_check		| attr_put_u64_check		|				|
| mnl_attr_put_str_check		| attr_put_str_check		|				|
| mnl_attr_put_strz_check		| attr_put_strz_check		|				|
| mnl_attr_nest_start_check		| attr_nest_start_check		| returns contents		|
| mnl_attr_nest_end			| attr_nest_end			|				|
| mnl_attr_nest_cancel			| attr_nest_cancel		|				|
| (add)					| mnl_attr_cb_t			| attr cb decorator		|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_nlmsg_size			| nlmsg_size			|				|
| mnl_nlmsg_get_payload_len		| nlmsg_get_payload_len		|				|
| mnl_nlmsg_put_header			| nlmsg_put_header		| buf must be mutable		|
| mnl_nlmsg_put_extra_header		| nlmsg_put_extra_header	| 				|
| (add)					| nlmsg_put_extra_header_v	| 				|
| (add)					| nlmsg_put_extra_header_as	| 				|
| mnl_nlmsg_get_paylod			| nlmsg_get_payload		|				|
| (add)					| nlmsg_get_payload_v		| returns array of c_ubyte	|
| (add)					| nlmsg_get_payload_as		| cast specified class		|
| mnl_nlmsg_get_payload_offset		| nlmsg_get_payload_offset	|				|
| mnl_nlmsg_ok				| nlmsg_ok			|				|
| mnl_nlmsg_next			| nlmsg_next			|				|
| mnl_nlmsg_get_payload_tail		| nlmsg_get_payload_tail	|				|
| mnl_nlmsg_seq_ok			| nlmsg_seq_ok			|				|
| mnl_nlmsg_portid_ok			| nlmsg_portid_ok		|				|
| mnl_nlmsg_fprintf			| nlmsg_fprint			| require file not descriptor	|
| mnl_nlmsg_batch_start			| nlmsg_batch_start		| require mutable buf		|
| mnl_nlmsg_batch_stop			| nlmsg_batch_stop		|				|
| mnl_nlmsg_batch_next			| nlmsg_batch_next		|				|
| mnl_nlmsg_batch_reset			| nlmsg_batch_reset		|				|
| mnl_nlmsg_batch_size			| nlmsg_batch_size		|				|
| mnl_nlmsg_batch_head			| nlmsg_batch_head		|				|
| (add)					| nlmsg_batch_head_v		|  returns array of c_ubyte	|
| mnl_nlmsg_batch_current		| nlmsg_batch_current		|				|
| mnl_nlmsg_batch_is_empty		| nlmsg_batch_is_empty		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_cb_run				| cb_run			| 				|
| mnl_cb_run2				| cb_run2			|				|
| (add)					| mnl_cb_t			| cb decorator			|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_socket_get_fd			| socket_get_fd			|				|
| mnl_socket_get_portid			| socket_get_portid		|				|
| mnl_socket_open			| socket_open			|				|
| mnl_socket_bind			| socket_bind			|				|
| mnl_socket_sendto			| socket_sendto			| require mutable buffer	|
| (add)					| socket_send_nlmsg		| pass nlmsghdr instead of buf	|
| mnl_socket_recvfrom			| socket_recv_into		|				|
| (add)					| socket_recv			| require buflen and returns	|
|					|				| mutable buffer not bytes	|
| mnl_socket_close			| socket_close			|				|
| mnl_socket_setsockopt			| socket_setsockopt		| require mutable buffer	|
| mnl_socket_getsockopt			| socket_getsockopt		| require buflen returns bytes	|
