//
// Created by victor on 6/8/18.
//

#ifndef PROJECT_ALLOC_H
#define PROJECT_ALLOC_H
#include <stddef.h>
int kinit(size_t size);
void *kalloc(const char *filename, size_t line, size_t size) __attribute__((flatten, alloc_size(3)));
void *krealloc(const char *filename, size_t line, void *ptr, size_t newsize) __attribute__((flatten));
void kfree(void *ptr) __attribute__((flatten));
void kdestroy();
void print_allocs(int handle, void (*writefn)(int handle, const char *fmt, ...));
#endif //PROJECT_ALLOC_H
