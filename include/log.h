#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>

// 初始化日志系统，指定日志文件名
// 如果filename为NULL，则输出到标准输出
int log_init(const char *filename);

// 关闭日志系统
void log_close();

// 记录日志
void log_write(int id, const char *format, ...);

void log_function_entry(int id, const char *func_name);
void log_function_exit(int id, const char *func_name);
#define LOG_FUNC_ENTRY(id) log_function_entry(id, __func__)
#define LOG_FUNC_EXIT(id) log_function_exit(id, __func__)

// 获取当前日志文件名
const char *log_get_filename();

#endif // LOG_H