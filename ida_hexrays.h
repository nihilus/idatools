
#define     _copy_from_user     memcpy
#define     _memzero(a,l)       memset((void*)a,0,l)
#define     copy_from_user      memcpy
#define     vfree               free

#define     vmalloc             malloc
#define		printk				printf