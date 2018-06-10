//
// Created by victor on 6/8/18.
//

#ifndef PROJECT_ALLOC_H
#define PROJECT_ALLOC_H
#include <stddef.h>
int kinit(size_t size);
void *kalloc(const char *filename, size_t line, size_t size);
void *krealloc(const char *filename, size_t line, void *ptr, size_t newsize);
void kfree(void *ptr);
void kdestroy();
void print_allocs(int handle, void (*writefn)(int handle, char *fmt, ...));
#endif //PROJECT_ALLOC_H
