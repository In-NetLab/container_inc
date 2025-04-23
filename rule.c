#include "rule.h"

int match_rule(rule_t* rule, uint32_t src_ip, uint32_t dst_ip) {
    return src_ip == rule->src_ip && dst_ip == rule->dst_ip;
}

rule_t* lookup_rule(rule_table_t* table, uint32_t src_ip, uint32_t dst_ip) {
    for(int i = 0; i < table->count; i++) {
        if(match_rule(&(table->rules[i]), src_ip, dst_ip) == 1)
            return &(table->rules[i]);
    }

    return NULL;
}

int add_rule(rule_table_t* table, const rule_t* rule) {
    if(table->count >= MAX_RULES)
        return -1;
    
    table->rules[table->count] = *rule;
    table->count++;

    return 0;
}

