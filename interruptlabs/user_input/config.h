#ifndef CONFIG_TYPES_H
#define CONFIG_TYPES_H

struct config;
typedef void (*handler_fn)(struct config *);

typedef struct config {
    char        hostname[0x32];   // offset 0x00
    char        ip[0x12];         // offset 0x32
    int         count;            // offset 0x44
    handler_fn  handler;          // offset 0x48 
} config;                         // total 0x50 bytes

#endif
