#include <yaml-cpp/yaml.h>
#include "topo_parser.h"
#include <vector>
#include <string>
#include <cstring>
#include "util.h"

std::vector<std::string> strings;

int parse_mac(const char* mac_str, uint8_t mac[6]) {
    if (mac_str == NULL) return -1;

    int values[6];
    int count = sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                       &values[0], &values[1], &values[2],
                       &values[3], &values[4], &values[5]);

    if (count != 6) {
        return -1;
    }

    for (int i = 0; i < 6; ++i) {
        mac[i] = (uint8_t)values[i];
    }

    return 0;
}

int parse_config(const char* yaml_file, int max_count, int* root, int switch_id, connection_t* conns) {
    YAML::Node config = YAML::LoadFile(yaml_file);
    int index = 0;
    for (const auto& sw : config["switches"]) {
        if (sw["id"].as<int>() == switch_id) {
            *root = sw["root"].as<bool>();

            for (const auto& conn : sw["connections"]) {
                if (index >= max_count) 
                    return index;
    
                auto store_string = [](const std::string& str) -> const char* {
                    strings.push_back(str);
                    return strings.back().c_str();
                };
    
                
                parse_mac(store_string(conn["my_mac"].as<std::string>()), conns[index].my_mac);
                parse_mac(store_string(conn["peer_mac"].as<std::string>()), conns[index].peer_mac);
                conns[index].my_ip = get_ip(store_string(conn["my_ip"].as<std::string>()));
                conns[index].peer_ip = get_ip(store_string(conn["peer_ip"].as<std::string>()));
                conns[index].my_port = conn["my_port"].as<int>();
                conns[index].peer_port = conn["peer_port"].as<int>();
                conns[index].my_qp = conn["my_qp"].as<int>();
                conns[index].peer_qp = conn["peer_qp"].as<int>();
                memcpy(conns[index].device, conn["my_name"].as<std::string>().c_str(), 4); //等会改一下yaml文件的格式，名字直接在yaml文件里指定。

                //print_connection(0, conns + index);
                index++;
            }

            return index;
        }
        
    }
    return -1;
}

int get_switch_info(const char* yaml_file, int rank, uint32_t *ip, uint32_t *qpnum) {
    YAML::Node config = YAML::LoadFile(yaml_file);

    for (const auto& sw : config["switches"]) {
        for (const auto& conn : sw["connections"]) {

            if(conn["host_id"].as<int>() == rank) {
                *ip = get_ip(conn["my_ip"].as<std::string>().c_str());
                *qpnum = conn["my_qp"].as<unsigned int>();
                return 0;
            }
        }
    }
    
    return -1;
}
