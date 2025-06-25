# 系统说明

本系统包括一个INC通信库，以及一个使用server端api发送数据的示例程序。

本系统不是一个out of box的系统，需要对controller里main函数的交换机初始化信息，例如交换机的用于控制的ip，以及各端口信息，以及controller_communicator::calculate_route函数里的拓扑结构以及server的mac信息。这个函数理论上利用controller收集到的拓扑结构进行计算配置文件，但是在本系统中，拓扑结构是固定的。

在运行程序前，需要首先配置整个环境。包括虚拟机组网，配置网卡和softroce，以及设置环境变量，为此我们提供了一些脚本，可以直接运行来配置环境。

# 环境配置脚本

可以按照顺序一次运行下面脚本，将脚本分为多个文件是为了方便用户根据自己的情况进行调试。由于multipass会将所有的虚拟机纳入一个默认的局域网（网卡名均为ens3），就可以将这个网络作为控制网络，但是由于这个默认网络ip是默认配置的，需要手动将controller和rank0的这个网卡的ip进行记录并写到启动示例程序的脚本中。

本拓扑结构为两层交换机，每一个交换机有两个子结点的二叉树结构。共有4个server，3个switch。控制器与每一个交换机/服务器相连。控制器拓扑独立于上述的树状拓扑，可以认为上述所有的虚拟机通过一个控制网桥彼此相连，这个网络是默认路由，只有点对点发送会经过上述二叉树拓扑的边。

- multiapass_load.sh 启动所有server，switch，controller虚拟机，并将他们连接到已有的逻辑veth-pair（使用两两之间网桥模拟veth-pair）
- multipass_address.sh 对每一个虚拟机的端口的ip地址进行配置
- rdma_config.sh 对每一个server虚拟机的端口配置softroce

# 示例程序

- task.sh 在虚拟机上启动对应的程序，需要修改server程序中rank0的地址，switch中controller的地址，以及通过配置环境变量，为每一个server配置controller地址的环境变量。
- host.c 在server端启动，使用了通信库的api完成allreduce。

switch程序获取controller地址是通过main函数的参数，而server中的rank0则是通过设置环境变量，这是因为真实交换机可能无法配置环境变量。

如果想正常运行，需要对task.sh脚本和controller.cpp/controller.h里的地址常量进行修改，如第一节所述。

整个流程为：先启动controller，再启动switch。之后，同时启动server，此时servers会将各自的信息发送给rank0，rank0将信息收集后转发给controller，这个过程使用socket。之后controller计算配置信息，并将这个配置文件发给rank0和所有的switch。switch收到会配置路由表等，rank0将其广播给所有的server，然后依据此信息初始化qp。这样一个通信组的通信器就完全初始化了，可以使用这个通信器调用allreduce等通信函数。

# INCCL通信库

## Server

```
api.c
```

- inccl_group_create 启动一个通信组

- inccl_communicator_create 在刚才的通信组中，启动一个通信器

  这是与之前唯一不同的地方，理论上一组拓扑确定的进程即group可以启动多个通信器，每一个通信器都维护各自的qp pair，并维护各自的路由拓扑。当然退回到之前的api也非常简单，只需要将这个函数放入group_create即可。启动通信**组**的时候会收集ip信息，通信**器**会收集qp number信息并计算拓扑、建立qp之间的伪连接。

- inccl_allreduce

## Switch

`switch.c`

可以直接运行，不需要更改程序。

- init_all 与控制器建立连接，并在新线程中等待控制器发回配置yaml文件。

## Controller

`controller.h/controller.cpp`

定义了一些描述拓扑结构的类，虽然本系统并没有使用这些数据动态计算拓扑。需要手动更改里面的拓扑数据。

## Utils

除上述文件，其他文件定义了一些辅助函数。