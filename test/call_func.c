/*
 *  try to call the VIVI's builtin function
 *
 *
 *  only for engineer test
 *
 *    bushi@mizi.com
 *
 */

int (*printk)(const char *fmt, ...);

int main()
{
	/* refer to ../vivi.map */
	printk = (0x33f04dec);

	printk("hello!\n");

	return 0;
}
