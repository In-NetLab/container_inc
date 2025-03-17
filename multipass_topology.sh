# without config the interface ip in the vm
# need to enter the vm to set the interface ip and set the right one up.
# fortunately I have set switch ip forwarding up and config the ip route table in this shell 
sudo ip link add br1 type bridge
sudo ip link set br1 up
sudo ip link add br2 type bridge
sudo ip link set br2 up
# need to config ip to 10.0.1.100/24
multipass launch --name server1 --mount /home/ruizhe/netlab/comm_lib:~/comm_lib --network name=br1,mode=manual --cloud-init ./load_rdma.yaml
# need to config ip to 10.0.2.100/24
multipass launch --name server2 --mount /home/ruizhe/netlab/comm_lib:~/comm_lib --network name=br2,mode=manual --cloud-init ./load_rdma.yaml
# need to config ip to 10.0.1.1/24, 10.0.2.1/24
multipass launch --name switch --mount /home/ruizhe/netlab/comm_lib:~/comm_lib --network name=br1,mode=manual --network name=br2,mode=manual --cloud-init ./load_rdma.yaml

multipass exec server1 -- sudo ip addr add  10.0.1.100/24 dev ens4
multipass exec server1 -- sudo ip link set ens4 up
multipass exec server1 -- sudo ip route add default via 10.0.1.1

multipass exec server2 -- sudo ip addr add  10.0.2.100/24 dev ens4
multipass exec server2 -- sudo ip link set ens4 up
multipass exec server2 -- sudo ip route add default via 10.0.2.1

multipass exec switch -- sudo ip addr add 10.0.1.1/24 dev ens4
multipass exec switch -- sudo ip addr add 10.0.2.1/24 dev ens5
multipass exec switch -- sudo ip link set ens4 up
multipass exec switch -- sudo ip link set ens5 up
multipass exec switch -- sudo sysctl -w net.ipv4.ip_forward=1

# config the ip in the vm respectively