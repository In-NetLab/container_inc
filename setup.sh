
ip link add A-ethAB type veth peer name B-ethAB

ip link set A-ethAB up
ip addr add 10.0.0.1/24 dev A-ethAB
ip link set B-ethAB up
ip addr add 10.0.0.2/24 dev B-ethAB

rdma link add rxe_a type rxe netdev A-ethAB
rdma link add rxe_b type rxe netdev B-ethAB