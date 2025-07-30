#include "controller.h"

switch_info switch_topology[TOPOLOGY_SIZE];

int controller_group::group_num = 0;
int controller_communicator::communicator_num = 10;


static void send_file_with_length(int fd, const char *file_path) {
    // 打开文件并获取大小
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("fopen failed");
        return;
    }

    // 获取文件大小
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // 转换为网络字节序
    uint32_t net_file_size = htonl((uint32_t)file_size);

    // 1. 发送文件长度（4字节）
    size_t sent = 0;
    while (sent < sizeof(net_file_size)) {
        ssize_t ret = send(fd, (char*)&net_file_size + sent, sizeof(net_file_size) - sent, 0);
        if (ret <= 0) {
            perror("send file size failed");
            fclose(file);
            return;
        }
        sent += ret;
    }

    // 2. 发送文件内容
    char buffer[4096];
    size_t total_sent = 0;
    while (total_sent < file_size) {
        // 读取文件块
        size_t to_read = (sizeof(buffer) < (file_size - total_sent)) ? sizeof(buffer) : (file_size - total_sent);
        size_t bytes_read = fread(buffer, 1, to_read, file);
        if (bytes_read <= 0) {
            perror("fread failed");
            break;
        }

        // 发送块
        sent = 0;
        while (sent < bytes_read) {
            ssize_t ret = send(fd, buffer + sent, bytes_read - sent, 0);
            if (ret <= 0) {
                perror("send file content failed");
                fclose(file);
                return;
            }
            sent += ret;
        }
        total_sent += sent;
    }

    printf("send file to fd: %d succeed.\n", fd);
    fclose(file);
}

static void group_session(int client_fd) {
    char req_type;
    ssize_t bytes;
    char buffer[4096];
    controller_group *group;
    int world_size;
    std::vector<controller_communicator *> comms;
    while (true) {
        // recv one byte as request type
        bytes = recv(client_fd, &req_type, 1, MSG_WAITALL);
        printf("begin to recv from rank0.\n");
        if(req_type == 'G'){
            // group logic
            bytes = recv(client_fd, &world_size, sizeof(int), MSG_WAITALL);
            group = new controller_group(world_size);
            for (int i = 0; i < world_size; ++i) {
                recv(client_fd, &group->ip_list[i], sizeof(uint32_t), MSG_WAITALL);
                printf("recv the ip %d.\n",group->ip_list[i]);
            }
            send(client_fd, &group->id, sizeof(uint32_t), 0);

        }
        else if(req_type == 'C'){
            // communicator logic
            controller_communicator *comm = new controller_communicator(group);
            comms.push_back(comm);
            // gather qp info
            for (int i = 0; i < world_size; ++i) {
                recv(client_fd, &comm->qp_list[i], sizeof(uint32_t), MSG_WAITALL);
                printf("recv the qp num %d.\n",comm->qp_list[i]);
            }
            
            // generate yaml
            comm->calculate_route(switch_topology);
            printf("route_calculated\n");
            // transfer yaml to rank0 and switches
            
            for(int i=0;i<TOPOLOGY_SIZE;++i){
                send(switch_topology[i].fd, &i, 4, 0);
            }

            printf("send id to switches.\n");

            for (int i = 0; i < TOPOLOGY_SIZE; ++i) {
                int fd = switch_topology[i].fd;
                send_file_with_length(fd, "/home/ubuntu/topology.yaml");
            }
            
            send_file_with_length(client_fd, "/home/ubuntu/topology.yaml");
        }
    }

    close(client_fd);
}

int main() {
    // init the priori knowledge
    std::map<std::string,switch_info> preknowledge_switchtopo;

    {// 之后从其他方式读取先验的所有交换机的信息，以及补充节点的信息
        switch_info info;
        // info.control_ip = "10.215.8.118";
        // info.id = 0;
        // info.ports.push_back({"ens4","10.0.4.1","52:54:00:12:e0:f5"});
        // info.ports.push_back({"ens5","10.0.5.1","52:54:00:21:b1:50"});
        // preknowledge_switchtopo["10.215.8.118"] = info;
        // info.ports.clear();
        // info.control_ip = "10.215.8.221";
        // info.id = 1;
        // info.ports.push_back({"ens4","10.0.0.1","52:54:00:57:fa:a3"});
        // info.ports.push_back({"ens5","10.0.1.1","52:54:00:5f:de:69"});
        // info.ports.push_back({"ens6","10.0.4.2","52:54:00:60:e0:a1"});
        // preknowledge_switchtopo["10.215.8.221"] = info;
        // info.ports.clear();
        // info.control_ip = "10.215.8.78";
        // info.id = 2;
        // info.ports.push_back({"ens4","10.0.2.1","52:54:00:e4:f6:fa"});
        // info.ports.push_back({"ens5","10.0.3.1","52:54:00:ed:37:6a"});
        // info.ports.push_back({"ens6","10.0.5.2","52:54:00:ef:a1:46"});
        // preknowledge_switchtopo["10.215.8.78"] = info;
        info.control_ip = "10.215.8.157";
        info.id = 0;
        info.ports.push_back({"ens4","10.0.0.1","52:54:00:51:87:bc"});
        info.ports.push_back({"ens5","10.0.1.1","52:54:00:57:4d:d5"});
        preknowledge_switchtopo["10.215.8.157"] = info;
    }

    // establish connections with all switches

    int controller_switch_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (controller_switch_fd < 0) {
        perror("socket creation failed");
        return 1;
    }

    int opt = 1;
    if (setsockopt(controller_switch_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        return 1;
    }

    sockaddr_in addr1{};
    addr1.sin_family = AF_INET;
    addr1.sin_addr.s_addr = INADDR_ANY;
    addr1.sin_port = htons(CONTROLLER_SWITCH_PORT);
    
    if (bind(controller_switch_fd, (sockaddr*)&addr1, sizeof(addr1)) < 0) {
        perror("bind failed");
        return 1;
    }

    if (listen(controller_switch_fd, 10) < 0) {
        perror("listen failed");
        return 1;
    }

    for(int i = 0;i<TOPOLOGY_SIZE;++i){
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        char client_ip[INET_ADDRSTRLEN];
        int sockfd = accept(controller_switch_fd, (sockaddr*)&client_addr, &addr_len);
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        switch_info &temp = preknowledge_switchtopo[client_ip];
        
        //std::cout << temp.id << std::endl;
        //std::cout << temp.ports.size() << std::endl;
        
        temp.fd = sockfd;
        switch_topology[temp.id] = temp;
        switch_topology[temp.id].fd = sockfd;
        //std::cout << switch_topology[temp.id].ports.size() << std::endl;
    }

    printf("connect with switches success.\n");
    // connections with rank0s
    int controller_group_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (controller_group_fd < 0) {
        perror("socket creation failed");
        return 1;
    }

    if (setsockopt(controller_group_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(CONTROLLER_GROUP_PORT);
    
    if (bind(controller_group_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        return 1;
    }

    if (listen(controller_group_fd, 5) < 0) {
        perror("listen failed");
        return 1;
    }

    while (true) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(controller_group_fd, (sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            perror("accept error");
            continue;
        }

        // 打印客户端信息
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        std::cout << "New connection from: " << client_ip 
                  << ":" << ntohs(client_addr.sin_port) << std::endl;

        // 创建会话线程
        std::thread(group_session, client_fd).detach();
    }

    close(controller_group_fd);
    return 0;

    
}