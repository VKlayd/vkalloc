//
// Created by victor on 6/8/18.
//

#include <stdlib.h>
#include <printf.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include <stdarg.h>

#include <vkalloc/vkalloc.h>

//#define DEBUG

#ifdef DEBUG
#define debug_print printf
#else
#define debug_print(a, ...)
#endif

#define pthread_mutex_lock(...)
#define pthread_mutex_unlock(...)

void *buf = NULL;

typedef struct {
    size_t ptr;
    size_t size;
} alloc_info;

#define FNAMESIZE 112
typedef struct alloc_header_t {
    size_t size;
    struct alloc_header_t *prev;
    struct alloc_header_t *next;
#ifdef STATS
    char file[FNAMESIZE];
    size_t line;
#endif
} alloc_header;

typedef struct {
    size_t table_size;
    alloc_info *table;
    alloc_info *orig_table;
    void *free_ptr;
    //size_t free_size;
    size_t allocated_size;
    size_t now_used;
    size_t max_used;
    pthread_mutex_t lock;
    alloc_header *head;
    alloc_header *tail;
} alloc_context;

alloc_context ctx;

alloc_context get_context(void);

alloc_context get_context(void) {
    return ctx;
}

#ifdef DEBUG
void print_table(void);
#endif

static inline int table_remove(size_t index) __attribute__ ((flatten));

static inline void init_mem_block(alloc_header *header, const char *filename, size_t line,
                                  size_t size) __attribute__ ((flatten, hot, , nonnull(1, 2)));

static inline int try_optimize_table(void) __attribute__ ((flatten));

static inline int remove_from_list(alloc_header *elem) __attribute__ ((flatten, hot, nonnull(1)));

static inline int emplace_in_list(alloc_header *new_elem) __attribute__ ((flatten, hot, nonnull(1)));

static inline int push_into_table(void *ptr) __attribute__ ((flatten, nonnull(1)));

static inline int try_merge_table_to_free(void) __attribute__ ((flatten));

static inline int table_insert(size_t index, void *ptr) __attribute__ ((flatten, nonnull(2)));

static inline int table_insert_internal(size_t index, size_t new_ptr, size_t pice_size) __attribute__ ((flatten));

static inline void merge_front(size_t index, size_t new_ptr, size_t pice_size) __attribute__ ((flatten, hot));

static inline void merge_back(size_t index, size_t pice_size) __attribute__ ((flatten, hot));

static inline size_t find_place(size_t ptr) __attribute__ ((flatten, hot));

static inline void *get_from_table(size_t size) __attribute__ ((flatten));

static inline void fill_header(alloc_header *hdr, size_t size, const char *filename,
                               size_t line) __attribute__ ((flatten, hot, nonnull(1, 3)));

int kinit(size_t size) {
    buf = malloc(size);
    ctx.orig_table = buf + size;
    ctx.table = buf + size;
    ctx.table_size = 0;
    ctx.free_ptr = buf;
    ctx.allocated_size = size;
    //ctx.allocated_size - ctx.now_used = size;
    ctx.now_used = 0;
    ctx.max_used = 0;
    pthread_mutex_init(&ctx.lock, NULL);
    ctx.head = NULL;
    ctx.tail = NULL;
    debug_print("initiated. free %lu %p\n", ctx.allocated_size - ctx.now_used, ctx.free_ptr);
    return 0;
}

static inline void fill_header(alloc_header *hdr, size_t size, const char *filename, size_t line) {
    hdr->size = size;
#ifdef STATS
    strncpy(hdr->file, filename, FNAMESIZE);
    hdr->line = line;
#endif
}

static inline void *get_from_table(size_t size) {
#ifdef DEBUG
    print_table();
#endif
    alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
    size_t i;
    int found_big_enough = 0;
    size_t first_big_enough = 0;
    size_t full_size = size + sizeof(alloc_header);
    for (i = 0; i < ctx.table_size; i++) {
        debug_print("[%lu]: %p[%lu]\n", i, table[i].ptr, table[i].size);
        if (found_big_enough == 0 && table[i].size > full_size) {
            found_big_enough = 1;
            first_big_enough = i;
            continue;
        }
        if (table[i].size == full_size) {
            void *return_ptr = (void *) (table[i].ptr);
            table_remove(i);
            debug_print("got place for %p in table. full.\n", return_ptr);
#ifdef DEBUG
            print_table();
#endif
            return return_ptr;
        }
    }
    if (found_big_enough) {
        void *return_ptr = (void *) (table[first_big_enough].ptr);
        table[first_big_enough].size -= full_size;
        table[first_big_enough].ptr += full_size;
        debug_print("got place for %p in table. peaced.\n", return_ptr);
#ifdef DEBUG
        print_table();
#endif
        return return_ptr;
    }

    debug_print("not found place in table\n");
    return NULL;
}

static inline size_t find_place(size_t ptr) {
    if (ctx.table_size == 0)
        return 0;
    alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
    size_t start = 0;
    size_t end = ctx.table_size - 1;
    while (start < end) {
        if (ptr < table[start].ptr)
            return start;
        if (ptr > table[end].ptr)
            return end + 1;
        if (start + 1 == end) {
            return end;
        }
        size_t mid = start + (end - start) / 2;
        if (ptr < table[mid].ptr) {
            end = mid;
        }
        if (ptr > table[mid].ptr) {
            start = mid;
        }
        if (ptr == table[mid].ptr) {
            assert(0);
        }
    }
    return end;
}

#ifdef DEBUG
void print_table(void) {
    alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
    debug_print("table ptr %p (%p, %lu)\n", table, ctx.table, ctx.table_size);
    size_t i;
    for (i = 0; i< ctx.table_size; i++) {
        debug_print("(%p) [%lu]: %p[%lu]\n", &table[i], i, table[i].ptr, table[i].size);
    }
};
#endif

static inline void merge_back(size_t index, size_t pice_size) {
    alloc_info *table = ctx.table - ctx.table_size;
    debug_print("MERGE 1!\n");
    table[index].size += pice_size + sizeof(alloc_header);
#ifdef DEBUG
    print_table();
#endif

    if (table[index].ptr + table[index].size == table[index + 1].ptr) {
        table[index].size += table[index + 1].size;
        table_remove(index + 1);
    }
#ifdef DEBUG
    print_table();
#endif
}

static inline void merge_front(size_t index, size_t new_ptr, size_t pice_size) {
    alloc_info *table = ctx.table - ctx.table_size;
    debug_print("MERGE 1b!\n");
    table[index].ptr = new_ptr;
    table[index].size += pice_size + sizeof(alloc_header);
    if (table[index - 1].ptr + table[index - 1].size == table[index].ptr) {
        table[index - 1].size += table[index].size;
        table_remove(index);
    }
}

static inline int table_insert_internal(size_t index, size_t new_ptr, size_t pice_size) {
    if (index == ctx.table_size && ctx.table < ctx.orig_table) {
        ctx.table[0].ptr = new_ptr;
        ctx.table[0].size = pice_size + sizeof(alloc_header);
        ctx.table += 1;
        ctx.table_size += 1;

        return 0;
    }
    alloc_info *table = ctx.table - ctx.table_size;
    alloc_info *new_table = table - 1;//sizeof(alloc_info);
    memmove(new_table, table, sizeof(alloc_info) * index);
    new_table[index].ptr = new_ptr;
    new_table[index].size = pice_size + sizeof(alloc_header);
    ctx.table_size += 1;
    ctx.now_used += sizeof(alloc_info);
    if (ctx.now_used > ctx.max_used) {
        ctx.max_used = ctx.now_used;
    }
    return 0;
}

static inline int table_insert(size_t index, void *ptr) {
    debug_print("insert id %lu\n", index);
    size_t real_ptr = (size_t) ptr - sizeof(alloc_header);
    alloc_header *header = ptr - sizeof(alloc_header);
    size_t pice_size = header->size;
    alloc_info *table = ctx.table - ctx.table_size;
    debug_print("check %lu == %lu\n", table[index].ptr + table[index].size, real_ptr);
    if (table[index].ptr + table[index].size == real_ptr) {
        merge_back(index, pice_size);
        return 0;
    }
    debug_print("check %lu == %lu\n", table[index].ptr, (size_t) ptr + pice_size);
    if (table[index].ptr == (size_t) ptr + pice_size) {
        merge_front(index, real_ptr, pice_size);
        return 0;
    }
    if (index < ctx.table_size) {
        debug_print("check %lu == %lu\n", table[index + 1].ptr + table[index + 1].size, real_ptr);
        if (table[index + 1].ptr + table[index + 1].size == real_ptr) {
            merge_back(index + 1, pice_size);
            return 0;
        }
        debug_print("check %lu == %lu\n", table[index + 1].ptr, (size_t) ptr + header->size);
        if (table[index + 1].ptr == (size_t) ptr + header->size) {
            merge_front(index + 1, real_ptr, pice_size);
            return 0;
        }
    }

    table_insert_internal(index, real_ptr, pice_size);

    return 0;
}

static inline int table_remove(size_t index) {
    debug_print("remove id %lu\n", index);
#ifdef DEBUG
    print_table();
#endif
    if (index == ctx.table_size - 1) {
        debug_print("remove last\n");
        ctx.table -= 1;
        ctx.table_size -= 1;
        if (ctx.table_size == 0) {
            ctx.now_used -= sizeof(alloc_info) * (ctx.orig_table - ctx.table);
            ctx.table = ctx.orig_table;
        }
        return 0;
    }
    if (index > 0) {
        alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
        alloc_info *new_table = table + 1;
        memmove(new_table, table, sizeof(alloc_info) * index);
    }
    ctx.table_size -= 1;
    ctx.now_used -= sizeof(alloc_info);
#ifdef DEBUG
    print_table();
#endif
    return 0;
}

static inline int try_merge_table_to_free(void) {
    if (ctx.table_size > 0) {
        size_t size = ctx.table[-1].size;
        size_t ptr = ctx.table[-1].ptr;
        debug_print("%lu <> %lu\n", ptr + size, (size_t) ctx.free_ptr);
        if (ptr + size == (size_t) ctx.free_ptr) {
            ctx.free_ptr = (void *) ptr;
            table_remove(ctx.table_size - 1);
        }
    }
    return 0;
}

static inline int push_into_table(void *ptr) {
    size_t place = find_place((size_t) ptr);
    debug_print("found place for %p in table %lu\n", ptr, place);
    table_insert(place, ptr);
    if (place == ctx.table_size)
        try_merge_table_to_free();
#ifdef DEBUG
    print_table();
#endif
    return 0;
}

static inline int emplace_in_list(alloc_header *new_elem) {
    new_elem->prev = ctx.tail;
    new_elem->next = NULL;
    if (ctx.tail == NULL) {
        ctx.tail = new_elem;
        ctx.head = new_elem;
        return 0;
    }
    ctx.tail->next = new_elem;
    ctx.tail = new_elem;
    return 0;
}

static inline int remove_from_list(alloc_header *elem) {
    if (ctx.head == elem) {
        ctx.head = elem->next;
    }
    if (elem == ctx.tail) {
        ctx.tail = elem->prev;
    }
    if (elem->next)
        elem->next->prev = elem->prev;
    if (elem->prev)
        elem->prev->next = elem->next;
    return 0;
}

static inline int try_optimize_table() {
    size_t step = ctx.orig_table - ctx.table;
    if (step > 0) {
        memmove(ctx.orig_table + ctx.table_size, ctx.table + ctx.table_size, sizeof(alloc_info) * step);
        ctx.now_used -= sizeof(alloc_info) * step;
    }
}

static inline void init_mem_block(alloc_header *header, const char *filename, size_t line, size_t size) {
    fill_header(header, size, filename, line);
    size_t full_size = size + sizeof(alloc_header);
    ctx.now_used += full_size;
    if (ctx.now_used > ctx.max_used) {
        ctx.max_used = ctx.now_used;
    }
    emplace_in_list(header);
}

void *kalloc(const char *filename, size_t line, size_t size) {
    debug_print("try allocate %lu\n", size);
    if (!buf) {
        exit(-1);
    }
    size = ((size >> 6) + 1) << 6;
    size_t full_size = size + sizeof(alloc_header);
    pthread_mutex_lock(&ctx.lock);
    if (ctx.allocated_size - ctx.now_used < full_size) {
        try_optimize_table();
        if (ctx.allocated_size - ctx.now_used < full_size) {
            pthread_mutex_unlock(&ctx.lock);
            printf("no place for %lu (%lu)\n", size, ctx.allocated_size - ctx.now_used);
            return NULL;
        }
    }

    if (ctx.table_size) {
        void *bl = get_from_table(size);
        if (bl) {
            init_mem_block(bl, filename, line, size);
            pthread_mutex_unlock(&ctx.lock);
            debug_print("alloc [%p %lu] free %lu %p\n", bl, size + sizeof(alloc_header),
                        ctx.allocated_size - ctx.now_used, ctx.free_ptr);
            return bl + sizeof(alloc_header);
        }
    }

    if (ctx.free_ptr + full_size > ctx.table - ctx.table_size) {
        try_optimize_table();
        if (ctx.free_ptr + full_size > ctx.table - ctx.table_size) {
            pthread_mutex_unlock(&ctx.lock);
            printf("no place for %lu (%lu but fragmented)\n", size, ctx.allocated_size - ctx.now_used);
            return NULL;
        } else {
            pthread_mutex_unlock(&ctx.lock);
            return kalloc(filename, line, size);
        }
    }

    alloc_header *s = ctx.free_ptr;
    init_mem_block(s, filename, line, size);

    ctx.free_ptr += full_size;

    debug_print("alloc [%p %lu] free %lu %p\n", s, size + sizeof(alloc_header), ctx.allocated_size - ctx.now_used,
                ctx.free_ptr);
    pthread_mutex_unlock(&ctx.lock);
    return ((void *) s) + sizeof(alloc_header);
}

void kfree(void *ptr) {
    if (!ptr)
        return;
    pthread_mutex_lock(&ctx.lock);
    debug_print("free %p\n", ptr);
    alloc_header *s = ptr - sizeof(alloc_header);
    size_t full_size = s->size + sizeof(alloc_header);
    remove_from_list(s);
    if ((ptr + s->size) == ctx.free_ptr) {
        ctx.free_ptr = ptr - sizeof(alloc_header);
        ctx.now_used -= full_size;
        try_merge_table_to_free();
        pthread_mutex_unlock(&ctx.lock);
        debug_print("1dealloc [%p %lu] free %lu %p\n", ptr, s->size + sizeof(alloc_header),
                    ctx.allocated_size - ctx.now_used, ctx.free_ptr);
        return;
    }
    push_into_table(ptr);
    ctx.now_used -= full_size;
    pthread_mutex_unlock(&ctx.lock);
    debug_print("2dealloc [%p %lu] free %lu %p\n", ptr, s->size + sizeof(alloc_header),
                ctx.allocated_size - ctx.now_used, ctx.free_ptr);
}

void *krealloc(const char *filename, size_t line, void *ptr, size_t newsize) {
    void *newptr = NULL;
    if (ptr) {
        alloc_header *hdr = ptr + sizeof(alloc_header);
        size_t size = hdr->size;
        if (newsize <= size)
            return ptr;
        u_int8_t tmp_buf[size];
        memcpy(tmp_buf, ptr, size);
        kfree(ptr);
        if (newsize > 0) {
            newptr = kalloc(filename, line, newsize);
            if (newptr)
                memcpy(newptr, tmp_buf, size);
        }
    } else {
        if (newsize > 0) {
            newptr = kalloc(filename, line, newsize);
        }
    }
    return newptr;
}

void kdestroy(void) {
    free(buf);
}

static void defWrite(int handle, const char *fmt, ...) {
    va_list args;
    char print_buf[512];

    va_start(args, fmt);
    vsprintf(print_buf, fmt, args);
    va_end(args);
    printf(print_buf);
}

void print_allocs(int handle, void (*writefn)(int handle, const char *fmt, ...)) {
    if (!writefn) {
        writefn = defWrite;
    }
    pthread_mutex_lock(&ctx.lock);
#ifdef STATS
    alloc_header *elem = ctx.head;
    (*writefn)(handle,"Currently allocated [block: %lu; free: %lu; now_used: %lu; max_used: %lu]:\n", ctx.allocated_size, ctx.allocated_size - ctx.now_used, ctx.now_used, ctx.max_used);
    while (elem) {
        (*writefn)(handle,"[%p] %s:%lu (%lu)\n", (void*)elem + sizeof(alloc_header), elem->file, elem->line, elem->size);
        elem = elem->next;
    }
#else
    (*writefn)(handle, "Currently allocated [block: %lu; free: %lu; now_used: %lu; max_used: %lu]:\n",
               ctx.allocated_size, ctx.allocated_size - ctx.now_used, ctx.now_used, ctx.max_used);
#endif
    alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
    (*writefn)(handle, "\nFree nodes table size: %lu [use %ld of memory + %ld]\n", ctx.table_size,
               ctx.table_size * sizeof(alloc_info), ctx.orig_table - ctx.table);
    size_t i;
    for (i = 0; i < ctx.table_size; i++) {
        (*writefn)(handle, "[%lu]: %p (%lu)\n", i, table[i].ptr, table[i].size);
    }

    pthread_mutex_unlock(&ctx.lock);
}
