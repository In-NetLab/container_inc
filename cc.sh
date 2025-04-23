gcc switch.c api.c util.c log.c rule.c -o output/switch -libverbs -pthread -lpcap
gcc host.c api.c util.c log.c rule.c -o output/host -libverbs -pthread
