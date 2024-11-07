##! Establish ZeroMQ connectivity with the broker.

@load ./main

module Cluster::Backend::ZeroMQ;


event zeek_init() &priority=10
	{
	if ( run_proxy_thread )
		Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread();

	Cluster::init();

	# Get things going by subscribing to our own topic.
	Cluster::subscribe(Cluster::nodeid_topic(Cluster::node_id()));
	}
