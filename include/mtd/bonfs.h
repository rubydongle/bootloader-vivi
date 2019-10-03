#ifndef _VIVI_BONFS_H_
#define _VIVI_BONFS_H_

int write_bon_image(struct mtd_info *mtd, ulong offset, char *src, long size);
int read_bon_partition(struct mtd_info *mtd);

#endif /* _VIVI_BONFS_H_ */
