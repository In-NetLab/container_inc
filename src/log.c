#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>


static FILE *log_file = NULL;
static char *log_filename = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

int log_init(const char *filename) {
    pthread_mutex_lock(&log_mutex);
    
    // 如果已经初始化过，先关闭之前的
    if (log_file != NULL && log_file != stdout && log_file != stderr) {
        fclose(log_file);
    }
    if (log_filename != NULL) {
        free(log_filename);
        log_filename = NULL;
    }
    
    // 打开新的日志文件
    if (filename != NULL) {
        log_file = fopen(filename, "w");
        if (log_file == NULL) {
            pthread_mutex_unlock(&log_mutex);
            return -1;
        }
        
        // 保存文件名
        log_filename = strdup(filename);
        if (log_filename == NULL) {
            fclose(log_file);
            log_file = NULL;
            pthread_mutex_unlock(&log_mutex);
            return -1;
        }
    } else {
        log_file = stdout;
    }
    
    pthread_mutex_unlock(&log_mutex);
    return 0;
}

void log_close() {
    pthread_mutex_lock(&log_mutex);
    
    if (log_file != NULL && log_file != stdout && log_file != stderr) {
        fclose(log_file);
        log_file = NULL;
    }
    
    if (log_filename != NULL) {
        free(log_filename);
        log_filename = NULL;
    }
    
    pthread_mutex_unlock(&log_mutex);
}

void log_write(int id, const char *format, ...) {
    return;
    va_list args;
    struct timeval tv;
    struct tm tm;
    char time_buf[64];
    pthread_t self = pthread_self();
    
    // 获取当前时间
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
    
    pthread_mutex_lock(&log_mutex);
    
    if (log_file == NULL) {
        log_file = stdout;
    }
    
    // 打印时间戳和线程ID
    fprintf(log_file, "[%s.%03ld][%lu] ", time_buf, tv.tv_usec / 1000, (unsigned long)self);

    
    fprintf(log_file, "[connection id: %d]  ", id);
    
    
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    // 确保每条日志单独一行
    fprintf(log_file, "\n");
    
    // 立即刷新，防止日志丢失
    fflush(log_file);
    
    pthread_mutex_unlock(&log_mutex);
}

void log_function_entry(int id, const char *func_name) {
    log_write(id, "==============> %s\n", func_name);
}
void log_function_exit(int id, const char *func_name) {
    log_write(id, "<============== %s\n", func_name);
}

const char *log_get_filename() {
    return log_filename;
}