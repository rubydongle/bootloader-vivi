#include <printk.h>
#include "machine.h"

int main()
{
	int i;
	unsigned long ticks;

	printk("\ntimer test code\n");

	OIER = 0x0;
	OWER = 0x0;
	OSMR0 = 0;
	OSSR = 0xf;
	OIER |= OIER_E0;
	OSCR = 0;


	OSSR = OSSR_M0;

	ticks = (3686400 * (10)) / (1000);
	printk("ticks = %d\n", ticks);
	OSMR0 = (OSCR + ticks);


	while (!(OSSR & OSSR_M0)) ;

	printk("OSSR = 0x%08lx\n", OSSR);
	printk("OK\n");

	return 0;
}
