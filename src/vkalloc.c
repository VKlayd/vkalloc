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

#define debug_print(a,...)

void *buf = NULL;

typedef struct {
    size_t ptr;
    size_t size;
} alloc_info;

#define FNAMESIZE 254
typedef struct alloc_header_t{
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
    void *free_ptr;
    size_t free_size;
    size_t allocated_size;
    size_t now_used;
    size_t max_used;
    pthread_mutex_t lock;
    alloc_header *head;
    alloc_header *tail;
} alloc_context;

alloc_context ctx;

alloc_context get_context() {
    return ctx;
}
void print_table();
int table_remove(size_t index);

int kinit(size_t size) {
    buf = malloc(size);
    ctx.table = buf + size;
    ctx.table_size = 0;
    ctx.free_ptr = buf;
    ctx.allocated_size = size;
    ctx.free_size = size;
    ctx.now_used = 0;
    ctx.max_used = 0;
    pthread_mutex_init(&ctx.lock, NULL);
    ctx.head = NULL;
    ctx.tail = NULL;
    debug_print("initiated. free %lu %p\n", ctx.free_size, ctx.free_ptr);
    return 0;
}

void fill_header(alloc_header *hdr, size_t size, const char *filename, size_t line) {
    hdr->size = size;
#ifdef STATS
    strncpy(hdr->file, filename, FNAMESIZE);
    hdr->line = line;
#endif
}

void *get_from_table(size_t size) {
    print_table();
    alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
	size_t i;
	int found_big_enough = 0;
	size_t first_big_enough = 0;
    for (i = 0; i< ctx.table_size; i++) {
        debug_print("[%lu]: %p[%lu]\n", i, table[i].ptr, table[i].size);
        if (table[i].size >= size + sizeof(alloc_header)) {
            if (table[i].size > size + sizeof(alloc_header) && found_big_enough == 0) {
                found_big_enough = 1;
                first_big_enough = i;
                continue;
            }
            //alloc_header *header = (alloc_header *)table[i].ptr;
            //header->size = size;
            void *return_ptr = (void *)(table[i].ptr + sizeof(alloc_header));
            table_remove(i);
            debug_print("got place for %p in table. full.\n", return_ptr);
            print_table();
            return return_ptr;
        }
    }
    if (found_big_enough)
    {
        //alloc_header *header = (alloc_header *)table[i].ptr;
        //header->size = size;
        void *return_ptr = (void *) (table[first_big_enough].ptr + sizeof(alloc_header));
        table[first_big_enough].size -= size + sizeof(alloc_header);
        table[first_big_enough].ptr += size + sizeof(alloc_header);
        debug_print("got place for %p in table. peaced.\n", return_ptr);
        print_table();
        return return_ptr;
    }

    debug_print("not found place in table\n");
    return NULL;
}

size_t find_place(size_t ptr) {
    if (ctx.table_size == 0)
        return 0;
    alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
    size_t start = 0;
    size_t end = ctx.table_size-1;
    while (start < end)
    {
        if (ptr < table[start].ptr)
            return start;
        if (ptr > table[end].ptr)
            return end+1;
        if (start + 1 == end) {
            return end;
        }
        size_t mid = start + (end - start) / 2;
        if (ptr < table[mid].ptr)
        {
            end = mid;
        }
        if (ptr > table[mid].ptr)
        {
            start = mid;
        }
        if (ptr == table[mid].ptr)
        {
            assert(0);
        }
    }
    return end;
}

void print_table() {
    alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
    debug_print("table ptr %p (%p, %lu)\n", table, ctx.table, ctx.table_size);
	size_t i;
    for (i = 0; i< ctx.table_size; i++) {
        debug_print("(%p) [%lu]: %p[%lu]\n", &table[i], i, table[i].ptr, table[i].size);
    }
};

int table_insert(size_t index, void *ptr) {
    debug_print("insert id %lu\n", index);
    size_t real_ptr = (size_t)ptr - sizeof(alloc_header);
    alloc_header *header = ptr - sizeof(alloc_header);
    alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
    debug_print("check %lu == %lu\n", table[index].ptr + table[index].size, real_ptr);
    if (table[index].ptr + table[index].size == real_ptr)
    {
        debug_print("MERGE 1!\n");
//        table[index].ptr = real_ptr;
        table[index].size += header->size + sizeof(alloc_header);
        print_table();

        if (table[index].ptr + table[index].size == table[index+1].ptr) {
            table[index].size += table[index+1].size;
            table_remove(index+1);
        }
        print_table();
        return 0;
    }
    debug_print("check %lu == %lu\n", table[index].ptr, (size_t)ptr + header->size);
    if (table[index].ptr == (size_t)ptr + header->size)
    {
        debug_print("MERGE 1b!\n");
        table[index].ptr = real_ptr;
        table[index].size += header->size + sizeof(alloc_header);
        if (table[index-1].ptr + table[index-1].size == table[index].ptr) {
            table[index-1].size += table[index].size;
            table_remove(index);
        }
        return 0;
    }
    if (index < ctx.table_size)
    {
        debug_print("check %lu == %lu\n", table[index + 1].ptr + table[index + 1].size, real_ptr);
        if (table[index + 1].ptr + table[index + 1].size == real_ptr)
        {
            debug_print("MERGE 2!\n");
            table[index+1].size += header->size + sizeof(alloc_header);
            if (table[index+1].ptr + table[index].size == table[index+2].ptr) {
                table[index+1].size += table[index+2].size;
                table_remove(index+2);
            }
            return 0;
        }
        debug_print("check %lu == %lu\n", table[index + 1].ptr, (size_t) ptr + header->size);
        if (table[index + 1].ptr == (size_t) ptr + header->size)
        {
            debug_print("MERGE 2b!\n");
            table[index+1].ptr = real_ptr;
            table[index+1].size += header->size + sizeof(alloc_header);
            if (table[index].ptr + table[index].size == table[index-1].ptr) {
                table[index].size += table[index-1].size;
                table_remove(index-1);
            }
            return 0;
        }
    }


    alloc_info *new_table = table - 1;//sizeof(alloc_info);
    memmove(new_table, table, sizeof(alloc_info) * index);
    new_table[index].ptr = real_ptr;
    new_table[index].size = header->size + sizeof(alloc_header);
    ctx.table_size += 1;
    ctx.free_size -= sizeof(alloc_info);
    ctx.now_used += sizeof(alloc_info);
    if (ctx.now_used > ctx.max_used) {
        ctx.max_used = ctx.now_used;
    }
    return 0;
}

int table_remove(size_t index) {
    debug_print("remove id %lu\n", index);
    print_table();
    if (index > 0)
    {
        alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
        alloc_info *new_table = table + 1;
        memmove(new_table, table, sizeof(alloc_info) * index);
    }
    ctx.table_size -= 1;
    ctx.free_size += sizeof(alloc_info);
    ctx.now_used -= sizeof(alloc_info);
    print_table();
    return 0;
}

int try_merge_table_to_free() {
    if (ctx.table_size > 0)
    {
        debug_print("%lu <> %lu\n", ctx.table[-1].ptr + ctx.table[-1].size, (size_t) ctx.free_ptr);
        if (ctx.table[-1].ptr + ctx.table[-1].size == (size_t) ctx.free_ptr)
        {
            ctx.free_ptr = (void *) ctx.table[-1].ptr;
            table_remove(ctx.table_size - 1);
        }
    }
    return 0;
}

int push_into_table(void *ptr) {
    size_t place = find_place((size_t)ptr);
    debug_print("found place for %p in table %lu\n", ptr, place);
    table_insert(place, ptr);
    //alloc_header *header = ptr - sizeof(alloc_header);
    print_table();
    return 0;
}

int emplace_in_list(alloc_header *new_elem) {
    new_elem->prev = ctx.tail;
    new_elem ->next = NULL;
    if (ctx.tail == NULL) {
        ctx.tail = new_elem;
        ctx.head = new_elem;
        return 0;
    }
    ctx.tail->next = new_elem;
    ctx.tail = new_elem;
    return 0;
}

int remove_from_list(alloc_header *elem) {
    if (ctx.head == elem) {
        ctx.head = elem->next;
        //return 0;
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

void *kalloc(const char *filename, size_t line, size_t size) {
    debug_print("try allocate %lu\n", size);
    pthread_mutex_lock(&ctx.lock);
    if (ctx.free_size < (size + sizeof(alloc_header)))
    {
        pthread_mutex_unlock(&ctx.lock);
        debug_print("no place for %lu (%lu)\n", size, ctx.free_size);
        return NULL;
    }

    void * bl = get_from_table(size);
    if (bl)
    {
        alloc_header *header = (alloc_header *)(bl - sizeof(alloc_header));
        fill_header(header, size, filename, line);
        ctx.free_size -= size + sizeof(alloc_header);
        ctx.now_used += size + sizeof(alloc_header);
        if (ctx.now_used > ctx.max_used) {
            ctx.max_used = ctx.now_used;
        }
        emplace_in_list(header);
        pthread_mutex_unlock(&ctx.lock);
        debug_print("alloc [%p %lu] free %lu %p\n", bl, size + sizeof(alloc_header), ctx.free_size, ctx.free_ptr);
        return bl;
    }

    if (ctx.free_ptr + (size + sizeof(alloc_header)) > ctx.table - ctx.table_size) {
        pthread_mutex_unlock(&ctx.lock);
        debug_print("no place for %lu (%lu but fragmented)\n", size, ctx.free_size);
        return NULL;
    }

    bl = ctx.free_ptr + sizeof(alloc_header);
    ctx.free_ptr += size + sizeof(alloc_header);
    ctx.free_size -= size + sizeof(alloc_header);
    alloc_header *s = bl - sizeof(alloc_header);
    fill_header(s, size, filename, line);
    emplace_in_list(s);
    ctx.now_used += size + sizeof(alloc_header);
    if (ctx.now_used > ctx.max_used) {
        ctx.max_used = ctx.now_used;
    }
    debug_print("alloc [%p %lu] free %lu %p\n", bl, size + sizeof(alloc_header), ctx.free_size, ctx.free_ptr);
    pthread_mutex_unlock(&ctx.lock);
    return bl;
}

void kfree(void *ptr) {
	if (!ptr)
		return;
    pthread_mutex_lock(&ctx.lock);
    debug_print("free %p\n", ptr);
    alloc_header *s = ptr - sizeof(alloc_header);
    remove_from_list(s);
    if ((ptr + s->size) == ctx.free_ptr) {
        ctx.free_ptr = ptr - sizeof(alloc_header);
        ctx.free_size += s->size + sizeof(alloc_header);
        try_merge_table_to_free();
        ctx.now_used -= s->size + sizeof(alloc_header);
        pthread_mutex_unlock(&ctx.lock);
        debug_print("dealloc [%p %lu] free %lu %p\n", ptr, s->size + sizeof(alloc_header), ctx.free_size, ctx.free_ptr);
        return;
    }
    push_into_table(ptr);
    ctx.free_size += s->size + sizeof(alloc_header);
    try_merge_table_to_free();
    ctx.now_used -= s->size + sizeof(alloc_header);
    pthread_mutex_unlock(&ctx.lock);
    debug_print("dealloc [%p %lu] free %lu %p\n", ptr, s->size + sizeof(alloc_header), ctx.free_size, ctx.free_ptr);
}

void *krealloc(const char *filename, size_t line, void *ptr, size_t newsize) {
    alloc_header *hdr = ptr + sizeof(alloc_header);
    size_t size = hdr->size;
    u_int8_t buf[size];
    memcpy(buf, ptr, size);
    kfree(ptr);
    void *newptr = kalloc(filename, line, newsize);
    memcpy(newptr, buf, size);
    return newptr;
}

void kdestroy() {
    free(buf);
}

void defWrite(int handle, char *fmt, ...)
{
    va_list  args;
    char  buf[512];

    va_start(args, fmt);
    vsprintf(buf, fmt, args);
    va_end(args);
    printf(buf);
}

void print_allocs(int handle, void (*writefn)(int handle, char *fmt, ...)) {
    if (!writefn) {
        writefn = defWrite;
    }
    pthread_mutex_lock(&ctx.lock);
#ifdef STATS
    alloc_header *elem = ctx.head;
    (*writefn)(handle,"Currently allocated [block: %lu; free: %lu; now_used: %lu; max_used: %lu]:\n", ctx.allocated_size, ctx.free_size, ctx.now_used, ctx.max_used);
    while (elem) {
        (*writefn)(handle,"[%p] %s:%lu (%lu)\n", (void*)elem + sizeof(alloc_header), elem->file, elem->line, elem->size);
        elem = elem->next;
    }
#endif
    alloc_info *table = ctx.table - ctx.table_size;// * sizeof(alloc_info);
    (*writefn)(handle,"\nFree nodes table size: %lu [use %ld of memory]\n", ctx.table_size, ctx.table_size * sizeof(alloc_info));
    size_t i;
    for (i = 0; i< ctx.table_size; i++) {
        (*writefn)(handle,"[%lu]: %p (%lu)\n", i, table[i].ptr, table[i].size);
    }

    pthread_mutex_unlock(&ctx.lock);
}
