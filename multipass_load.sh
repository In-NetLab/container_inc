# without config the interface ip in the vm
# need to enter the vm to set the interface ip and set the right one up.
# fortunately I have set switch ip forwarding up and config the ip route table in this shell 
sudo ip link add br0 type bridge
sudo ip link set br0 up
sudo ip link add br1 type bridge
sudo ip link set br1 up
sudo ip link add br2 type bridge
sudo ip link set br2 up
sudo ip link add br3 type bridge
sudo ip link set br3 up
sudo ip link add br4 type bridge
sudo ip link set br4 up
sudo ip link add br5 type bridge
sudo ip link set br5 up

# need to config ip to 10.0.x.0/24
multipass launch --name server0 --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br0 --cloud-init ./load_rdma.yaml
multipass launch --name server1 --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br1 --cloud-init ./load_rdma.yaml
multipass launch --name server2 --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br2 --cloud-init ./load_rdma.yaml
multipass launch --name server3 --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br3 --cloud-init ./load_rdma.yaml


multipass launch --name switch0 --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br4 --network name=br5 --cloud-init ./load_rdma.yaml
multipass launch --name switch1 --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br0 --network name=br1 --network name=br4 --cloud-init ./load_rdma.yaml
multipass launch --name switch2 --mount /home/ruizhe/kvm_net/repository:~/repository --network name=br2 --network name=br3 --network name=br5 --cloud-init ./load_rdma.yaml

multipass launch --name controller --mount /home/ruizhe/kvm_net/repository:~/repository --cloud-init ./load_rdma.yaml
