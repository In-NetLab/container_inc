## 交换机配置、运行

- 连接配置
 `switch.c` `init_all()`中修改伪连接配置

 `host.c` `init_all()`中修改交换机伪ip
 
 TODO：配置文件读取 / 控制器配置分发

- 编译
    ``` bash
    ./cc.sh
    ```
- 运行
    ``` bash
    sudo output/switch # 终端1
    output/host 1 # 终端2
    output/host 2 # 终端3
    ```