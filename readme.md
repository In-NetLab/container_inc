## 交换机配置、运行

### 连接配置

#### C
 
1. `src/switch.c` `init_all()`中修改伪连接配置

2. `src/host.c` `init_all()`中修改交换机伪ip

3. `CMakeLists`中去掉`CONFIG_PARSER`以及`yaml-cpp`
 
#### CPP

0. 方便修改拓扑用于测试

1. 修改`config/xxx.yaml`

2. `src/switch.c` `init_all()` 和 `src/host.c` `init_all()` 中修改yaml文件路径

### 编译
``` bash
mkdir build && cd build
cmake ..
make
```
### 运行
``` bash
cd ..
sudo build/switch 0 # 终端1
build/host 1 # 终端2
build/host 2 # 终端3
```