#pragma once

#include <stdint.h>

#define FBIOGET_VSCREENINFO    0x4600
#define FBIOGET_FSCREENINFO    0x4602

struct fb_bitfield {
    uint32_t offset;        /* beginning of bitfield */
    uint32_t length;        /* length of bitfield */
    uint32_t msb_right;     /* != 0 : Most significant bit is */ 
                    /* right */ 
};

struct fb_var_screeninfo {
    uint32_t xres;             /* visible resolution */
    uint32_t yres;
    uint32_t xres_virtual;     /* virtual resolution */
    uint32_t yres_virtual;
    uint32_t xoffset;          /* offset from virtual to visible */
    uint32_t yoffset;          /* resolution */
    uint32_t bits_per_pixel;       /* guess what */
    struct fb_bitfield red;     /* bitfield in fb mem if true color, */
    struct fb_bitfield green;   /* else only length is significant */
    struct fb_bitfield blue;
    struct fb_bitfield transp;  /* transparency         */    
    uint32_t height;           /* height of picture in mm    */
    uint32_t width;            /* width of picture in mm     */
};