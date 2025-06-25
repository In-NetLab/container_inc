multipass exec server0 -- sudo ip addr add 10.0.0.2/24 dev ens4
multipass exec server0 -- sudo ip link set ens4 up

multipass exec server1 -- sudo ip addr add 10.0.1.2/24 dev ens4
multipass exec server1 -- sudo ip link set ens4 up

multipass exec switch -- sudo ip addr add 10.0.0.1/24 dev ens4
multipass exec switch -- sudo ip addr add 10.0.1.1/24 dev ens5
multipass exec switch -- sudo ip link set ens4 up
multipass exec switch -- sudo ip link set ens5 up
multipass exec switch -- sudo sysctl -w net.ipv4.ip_forward=1

multipass exec server0 -- sudo rdma link add rxe4 type rxe netdev ens4
multipass exec server1 -- sudo rdma link add rxe4 type rxe netdev ens4