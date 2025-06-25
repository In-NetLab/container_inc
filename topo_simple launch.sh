sudo ip link add br0 type bridge
sudo ip link set br0 up
sudo ip link add br1 type bridge
sudo ip link set br1 up

multipass launch --name server0 --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br0 --cloud-init ./load_rdma.yaml
multipass launch --name server1 --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br1 --cloud-init ./load_rdma.yaml


multipass launch --name switch --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br0 --network name=br1 --cloud-init ./load_rdma.yaml

multipass launch --name controller --mount /home/ruizhe/kvm_net/repository:~/repository --cloud-init ./load_rdma.yaml

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