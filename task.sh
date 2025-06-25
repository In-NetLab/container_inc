multipass exec controller -- bash -c '~/repository/build/controller > ~/repository/log/controller.log'
multipass exec switch0 -- bash -c '~/repository/build/switch 10.215.8.163 > ~/repository/log/switch0.log'
multipass exec switch1 -- bash -c '~/repository/build/switch 10.215.8.163 > ~/repository/log/switch1.log'
multipass exec switch2 -- bash -c '~/repository/build/switch 10.215.8.163 > ~/repository/log/switch2.log'

multipass exec server0 -- bash -c 'echo 'export CONTROLLER_IP="10.215.8.163"' >> ~/.bashrc'
echo 'export CONTROLLER_IP="10.215.8.149"' >> ~/.bashrc
source ~/.bashrc 
multipass exec server1 -- bash -c 'echo 'export CONTROLLER_IP="10.215.8.163"' >> ~/.bashrc'
multipass exec server2 -- bash -c 'echo 'export CONTROLLER_IP="10.215.8.163"' >> ~/.bashrc'
multipass exec server3 -- bash -c 'echo 'export CONTROLLER_IP="10.215.8.163"' >> ~/.bashrc'

multipass exec server0 -- bash -c '~/repository/build/host 4 10.215.8.160 0 > ~/repository/log/server0.log'
multipass exec server1 -- bash -c '~/repository/build/host 4 10.215.8.160 1 > ~/repository/log/server1.log'
multipass exec server2 -- bash -c '~/repository/build/host 4 10.215.8.160 2 > ~/repository/log/server2.log'
multipass exec server3 -- bash -c '~/repository/build/host 4 10.215.8.160 3 > ~/repository/log/server3.log'
