#include <yaml-cpp/yaml.h>
#include <vector>
#include <fstream>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <byteswap.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/time.h>
#include <map>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <thread>
#include "parameter.h"


struct switch_port{
    std::string name;
    std::string ip;
    std::string mac;
};

struct switch_info{
    int fd;
    int id;
    std::string control_ip;
    std::vector<switch_port> ports;
    //maybe other info to add
};


extern switch_info switch_topology[TOPOLOGY_SIZE];

// 定义连接配置结构体
struct ConnectionConfig {
    bool up;
    int host_id;
    std::string my_ip;
    std::string my_mac;
    std::string my_name;
    int my_port;
    int my_qp;
    std::string peer_ip;
    std::string peer_mac;
    int peer_port;
    int peer_qp;
};

// 定义交换机配置结构体
struct SwitchConfig {
    int id;
    bool root;
    std::vector<ConnectionConfig> connections;
};

// YAML 序列化适配器
namespace YAML {
template<>
struct convert<ConnectionConfig> {
    static Node encode(const ConnectionConfig& conn) {
        Node node;
        node["up"] = conn.up;
        node["host_id"] = conn.host_id;
        node["my_ip"] = conn.my_ip;
        node["my_mac"] = conn.my_mac;
        node["my_name"] = conn.my_name;
        node["my_port"] = conn.my_port;
        node["my_qp"] = conn.my_qp;
        node["peer_ip"] = conn.peer_ip;
        node["peer_mac"] = conn.peer_mac;
        node["peer_port"] = conn.peer_port;
        node["peer_qp"] = conn.peer_qp;
        return node;
    }
};

template<>
struct convert<SwitchConfig> {
    static Node encode(const SwitchConfig& sw) {
        Node node;
        node["id"] = sw.id;
        node["root"] = sw.root;
        node["connections"] = sw.connections;
        return node;
    }
};
}


struct controller_group{
    int id;
    int world_size;
    uint32_t *ip_list; // index is rank
    static int group_num;

    controller_group(int ws):world_size(ws){
        id = ++group_num;
        ip_list = new uint32_t(ws);
    }

    ~controller_group(){
        delete ip_list;
    }
};

struct controller_communicator{
    controller_group *group;
    int id;
    uint32_t *qp_list;
    std::vector<SwitchConfig> switches;
    static int communicator_num;
    controller_communicator(controller_group *g):group(g){
        qp_list = new uint32_t(g->world_size);
        id = ++communicator_num;
    }

    void calculate_route(void *topology_info){
        // generate the switches field
        // now just write the fixed data
        printf("in function calculate_route\n");
        for(int i=0;i<TOPOLOGY_SIZE;++i){
            auto &info = switch_topology[i];
            std::cout << info.id << std::endl;
            std::cout << info.ports.size() << std::endl;
            SwitchConfig sc;
            if(info.id==0){ sc.root = true;}
            else {sc.root = false;}
            sc.id = info.id;
            int index;
            int j = 0;
            for(auto &port:info.ports){
                ConnectionConfig cc;
                cc.my_ip = port.ip;
                std::cout << cc.my_ip << std::endl;
                cc.my_mac = port.mac;
                std::cout << cc.my_mac << std::endl;
                cc.my_name = port.name;
                std::cout << cc.my_name << std::endl;
                cc.my_port = 4791;
                cc.my_qp = id+(j++); // it will be
                sc.connections.push_back(cc);
            }
            switches.push_back(sc);
        }
        
        
        printf("in function calculate_route 151th line\n");
        printf("%ld\n", switches.size());
        // idealy by calulation, below is in manual set.

        char rankip[INET_ADDRSTRLEN];
        struct in_addr addr;
        //rank 0
        switches[0].connections[0].up = false;
        switches[0].connections[0].host_id = 0;
        addr.s_addr = group->ip_list[0]; 
        inet_ntop(AF_INET, &addr, rankip, INET_ADDRSTRLEN); 
        switches[0].connections[0].peer_ip = rankip;
        switches[0].connections[0].peer_mac = "52:54:00:a0:e6:9a"; // need to config manually
        switches[0].connections[0].peer_port = 4791;
        switches[0].connections[0].peer_qp = qp_list[0];
        //rank 1
        switches[0].connections[1].up = false;
        switches[0].connections[1].host_id = 1;
        addr.s_addr = group->ip_list[1]; 
        inet_ntop(AF_INET, &addr, rankip, INET_ADDRSTRLEN); 
        switches[0].connections[1].peer_ip = rankip;
        switches[0].connections[1].peer_mac = "52:54:00:07:1b:5b"; // need to config manually
        switches[0].connections[1].peer_port = 4791;
        switches[0].connections[1].peer_qp = qp_list[1];

        // switches[1].connections[1].up = false;
        // switches[1].connections[1].host_id = 1;
        // addr.s_addr = group->ip_list[1];
        // inet_ntop(AF_INET, &addr, rankip, INET_ADDRSTRLEN);
        // switches[1].connections[1].peer_ip = rankip;
        // switches[1].connections[1].peer_mac = "52:54:00:8d:53:ea";
        // switches[1].connections[1].peer_port = 4791;
        // switches[1].connections[1].peer_qp = qp_list[1];

        // switches[0].connections[0].up = false;
        // switches[0].connections[0].host_id = 101;

        // printf("in function calculate_route 157th line\n");

        // switches[0].connections[0].peer_ip = switch_topology[1].ports[2].ip;

        // printf("in function calculate_route 161th line\n");

        // switches[0].connections[0].peer_mac = switch_topology[1].ports[2].mac;

        // printf("in function calculate_route 165th line\n");

        // switches[0].connections[0].peer_port = 4791;
        // switches[0].connections[0].peer_qp = id;

        // switches[0].connections[1].up = false;
        // switches[0].connections[1].host_id = 102;

        // printf("in function calculate_route 173th line\n");

        // switches[0].connections[1].peer_ip = switch_topology[2].ports[2].ip;

        // printf("in function calculate_route 177th line\n");

        // switches[0].connections[1].peer_mac = switch_topology[2].ports[2].mac;
        // switches[0].connections[1].peer_port = 4791;
        // switches[0].connections[1].peer_qp = id;

        // char rankip[INET_ADDRSTRLEN];
        // struct in_addr addr;

        // switches[1].connections[0].up = false;
        // switches[1].connections[0].host_id = 0;
        // addr.s_addr = group->ip_list[0];
        // inet_ntop(AF_INET, &addr, rankip, INET_ADDRSTRLEN);
        // switches[1].connections[0].peer_ip = rankip;
        // switches[1].connections[0].peer_mac = "52:54:00:20:78:e5";
        // switches[1].connections[0].peer_port = 4791;
        // switches[1].connections[0].peer_qp = qp_list[0];

        // switches[1].connections[1].up = false;
        // switches[1].connections[1].host_id = 1;
        // addr.s_addr = group->ip_list[1];
        // inet_ntop(AF_INET, &addr, rankip, INET_ADDRSTRLEN);
        // switches[1].connections[1].peer_ip = rankip;
        // switches[1].connections[1].peer_mac = "52:54:00:8d:53:ea";
        // switches[1].connections[1].peer_port = 4791;
        // switches[1].connections[1].peer_qp = qp_list[1];

        // switches[1].connections[2].up = true;
        // switches[1].connections[2].host_id = 100;
        // switches[1].connections[2].peer_ip = switch_topology[0].ports[0].ip;
        // switches[1].connections[2].peer_mac = switch_topology[0].ports[0].mac;
        // switches[1].connections[2].peer_port = 4791;
        // switches[1].connections[2].peer_qp = id;

        // switches[2].connections[0].up = false;
        // switches[2].connections[0].host_id = 2;
        // addr.s_addr = group->ip_list[2];
        // inet_ntop(AF_INET, &addr, rankip, INET_ADDRSTRLEN);
        // switches[2].connections[0].peer_ip = rankip;
        // switches[2].connections[0].peer_mac = "52:54:00:01:06:ec";
        // switches[2].connections[0].peer_port = 4791;
        // switches[2].connections[0].peer_qp = qp_list[2];

        // switches[2].connections[1].up = false;
        // switches[2].connections[1].host_id = 3;
        // addr.s_addr = group->ip_list[3];
        // inet_ntop(AF_INET, &addr, rankip, INET_ADDRSTRLEN);
        // switches[2].connections[1].peer_ip = rankip;
        // switches[2].connections[1].peer_mac = "52:54:00:a3:3e:9d";
        // switches[2].connections[1].peer_port = 4791;
        // switches[2].connections[1].peer_qp = qp_list[3];

        // switches[2].connections[2].up = true;
        // switches[2].connections[2].host_id = 100;
        // switches[2].connections[2].peer_ip = switch_topology[0].ports[1].ip;
        // switches[2].connections[2].peer_mac = switch_topology[0].ports[1].mac;
        // switches[2].connections[2].peer_port = 4791;
        // switches[2].connections[2].peer_qp = id;
        
        printf("in function calculate_route 221th line\n");


        generate_yaml();
    }

    void generate_yaml() {
        YAML::Node root;
        root["switches"] = switches;
        
        std::ofstream fout("/home/ubuntu/topology.yaml");
        fout << root;
    }

    ~controller_communicator(){
        delete qp_list;
    }
};


