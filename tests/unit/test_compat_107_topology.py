from redagent_platform.network_service.topology import certified_topology


def test_r107_topology_has_only_a_dual_homed_gateway_and_no_published_ports() -> None:
    topology = certified_topology()
    assert topology.worker_network.internal and topology.target_network.internal
    assert topology.worker.networks == (topology.worker_network.name,)
    assert topology.target.networks == (topology.target_network.name,)
    assert set(topology.gateway.networks) == {topology.worker_network.name, topology.target_network.name}
    for workload in (topology.worker, topology.gateway, topology.target):
        assert workload.user == "65532:65532"
        assert workload.read_only and workload.no_new_privileges
        assert workload.cap_drop == ("ALL",)
        assert workload.published_ports == ()
