## 交换机配置、运行

- 连接配置
 `src/switch.c` `init_all()`中修改伪连接配置

 `src/host.c` `init_all()`中修改交换机伪ip
 
 TODO：配置文件读取 / 控制器配置分发

- 编译
    ``` bash
    mkdir build && cd build
    cmake ..
    make
    ```
- 运行
    ``` bash
    cd ..
    sudo build/switch # 终端1
    build/host 1 # 终端2
    build/host 2 # 终端3
    ```