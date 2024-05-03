#include <elf.h>

typedef struct encl_map_info {
	void *base;
	size_t size;
	void *entry_point;
	unsigned long ret_point;
	unsigned long syscall_handler;
	void * signal_handler;
	unsigned long cvm_heap_begin;
	unsigned long cvm_heap_size;
	void *cap_relocs;
	unsigned long cap_relocs_size;
	void *rela_dyn;
	unsigned long rela_dyn_size;
	unsigned long end_of_ro;
	unsigned long extra_load;
} encl_map_info;

void load_elf(char *file_to_map, void *base_addr, encl_map_info * result);
