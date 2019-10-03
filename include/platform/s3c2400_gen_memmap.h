#ifndef _VIVI_MEM_MAP_H_
#define _VIVI_MEM_MAP_H_

#define ROM_BASE0               0x00000000      /* base address of rom bank 0 */
#define ROM_BASE1               0x02000000      /* base address of rom bank 1 */
#define DRAM_BASE0              0x0C000000      /* base address of dram bank 0 */
#define DRAM_BASE1              0x0E000000      /* base address of dram bank 1 */

#define UNCACHED_FLASH_BASE     0x04000000
#define CACHE_FLUSH_BASE        0x08000000
#define CACHE_FLUSH_SIZE        SZ_16K

#endif /* _VIVI_MEM_MAP_H_ */
