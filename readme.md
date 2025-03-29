
## 交换机配置、运行

- `switch.c` `init_all()`中修改连接配置

- 编译
    ``` bash
    gcc switch.c api.c util.c log.c -o output/switch -libverbs -pthread -lpcap
    ```