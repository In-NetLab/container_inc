
multipass exec server0 -- sudo ip addr add  10.0.0.2/24 dev ens4
multipass exec server0 -- sudo ip link set ens4 up

multipass exec server1 -- sudo ip addr add  10.0.1.2/24 dev ens4
multipass exec server1 -- sudo ip link set ens4 up

multipass exec server2 -- sudo ip addr add  10.0.2.2/24 dev ens4
multipass exec server2 -- sudo ip link set ens4 up

multipass exec server3 -- sudo ip addr add  10.0.3.2/24 dev ens4
multipass exec server3 -- sudo ip link set ens4 up


multipass exec switch0 -- sudo ip addr add 10.0.4.1/24 dev ens4
multipass exec switch0 -- sudo ip addr add 10.0.5.1/24 dev ens5
multipass exec switch0 -- sudo ip link set ens4 up
multipass exec switch0 -- sudo ip link set ens5 up
multipass exec switch0 -- sudo sysctl -w net.ipv4.ip_forward=1

multipass exec switch1 -- sudo ip addr add 10.0.0.1/24 dev ens4
multipass exec switch1 -- sudo ip addr add 10.0.1.1/24 dev ens5
multipass exec switch1 -- sudo ip addr add 10.0.4.2/24 dev ens6
multipass exec switch1 -- sudo ip link set ens4 up
multipass exec switch1 -- sudo ip link set ens5 up
multipass exec switch1 -- sudo ip link set ens6 up
multipass exec switch1 -- sudo sysctl -w net.ipv4.ip_forward=1

multipass exec switch2 -- sudo ip addr add 10.0.2.1/24 dev ens4
multipass exec switch2 -- sudo ip addr add 10.0.3.1/24 dev ens5
multipass exec switch2 -- sudo ip addr add 10.0.5.2/24 dev ens6
multipass exec switch2 -- sudo ip link set ens4 up
multipass exec switch2 -- sudo ip link set ens5 up
multipass exec switch2 -- sudo ip link set ens6 up
multipass exec switch2 -- sudo sysctl -w net.ipv4.ip_forward=1

# config the ip in the vm respectively