// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2024 9elements GmbH
 */

#include <asm/cache.h>
#include <asm/io.h>
#include <asm/global_data.h>
#include <asm/system.h>
#include <asm/armv8/cpu.h>
#include <asm-generic/sections.h>
#include <cpu.h>
#include <cpu_func.h>
#include <dm.h>
#include <fdt_support.h>
#include <linux/bitops.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>

DECLARE_GLOBAL_DATA_PTR;

static int cpu_bcm_get_desc(const struct udevice *dev, char *buf, int size)
{
	struct cpu_plat *plat = dev_get_parent_plat(dev);
	const char *name;
	int ret;

	if (size < 32)
		return -ENOSPC;

	if (device_is_compatible(dev, "arm,cortex-a53"))
		name = "A53";
	else if (device_is_compatible(dev, "arm,cortex-a72"))
		name = "A72";
	else
		name = "?";

	ret = snprintf(buf, size, "Broadcom Cortex-%s at %u MHz",
		       name, plat->timebase_freq);

	snprintf(buf + ret, size - ret, "\n");

	return 0;
}

static int cpu_bcm_get_info(const struct udevice *dev, struct cpu_info *info)
{
	struct cpu_plat *plat = dev_get_parent_plat(dev);

	info->cpu_freq = plat->timebase_freq * 1000;
	info->features = BIT(CPU_FEAT_L1_CACHE) | BIT(CPU_FEAT_MMU);
	return 0;
}

static int cpu_bcm_get_count(const struct udevice *dev)
{
	ofnode node;
	int num = 0;

	ofnode_for_each_subnode(node, dev_ofnode(dev->parent)) {
		const char *device_type;

		if (!ofnode_is_enabled(node))
			continue;

		device_type = ofnode_read_string(node, "device_type");
		if (!device_type)
			continue;

		if (!strcmp(device_type, "cpu"))
			num++;
	}

	return num;
}

static int cpu_bcm_get_vendor(const struct udevice *dev,  char *buf, int size)
{
	snprintf(buf, size, "Broadcom");
	return 0;
}

#ifdef CONFIG_ARM64
static int cpu_bcm_is_current(struct udevice *dev)
{
	struct cpu_plat *plat = dev_get_parent_plat(dev);

	if (plat->cpu_id == (read_mpidr() & 0xffff))
		return 1;

	return 0;
}
#endif

static int bcm_cpu_on(struct udevice *dev)
{
	ofnode node = dev_ofnode(dev);
	uintptr_t *start_address;
	u64 release_addr64;
	const char *prop;

	if (!ofnode_is_enabled(node))
		return 0;

	prop = ofnode_read_string(node, "enable-method");
	if (!prop || strcmp(prop, "spin-table"))
		return 1;

	release_addr64 = ofnode_read_u64_default(node, "cpu-release-addr", ~0ULL);
	if (release_addr64 == ~0ULL)
		return 1;

	start_address = map_physmem(release_addr64, sizeof(uintptr_t), MAP_NOCACHE);

	/* Point to U-Boot start */
	*start_address = (uintptr_t)_start;
	flush_dcache_all();

	/* Send an event to wake up the secondary CPU. */
	asm("dsb	ishst\n"
	    "sev");
	udelay(10000);

	unmap_physmem(start_address, MAP_NOCACHE);
	return 0;
}

static int bcm_init(struct udevice *dev)
{
	int ret = 0;

	/* The armstub holds the secondary CPUs in a spinloop. When
	 * ARMV8_MULTIENTRY is enabled release the secondary CPUs and
	 * let them enter U-Boot as well.
	 */
	if (CONFIG_IS_ENABLED(ARMV8_MULTIENTRY))
		ret = bcm_cpu_on(dev);
	return ret;
}

static const struct cpu_ops cpu_bcm_ops = {
	.get_desc	= cpu_bcm_get_desc,
	.get_info	= cpu_bcm_get_info,
	.get_count	= cpu_bcm_get_count,
	.get_vendor	= cpu_bcm_get_vendor,
#ifdef CONFIG_ARM64
	.is_current	= cpu_bcm_is_current,
#endif
};

static const struct udevice_id cpu_bcm_ids[] = {
	{ .compatible = "arm,cortex-a53" },	/* RPi 3 */
	{ .compatible = "arm,cortex-a72" },	/* RPi 4 */
	{ }
};

static int cpu_bcm_bind(struct udevice *dev)
{
	struct cpu_plat *plat = dev_get_parent_plat(dev);

	plat->cpu_id = dev_read_addr(dev);

	return bcm_init(dev);
}

static int bcm_cpu_probe(struct udevice *dev)
{
	struct cpu_plat *plat = dev_get_parent_plat(dev);
	struct clk clk;
	int ret;

	/* Get a clock if it exists */
	ret = clk_get_by_index(dev, 0, &clk);
	if (!ret) {
		ret = clk_enable(&clk);
		if (ret && (ret != -ENOSYS || ret != -EOPNOTSUPP))
			return ret;
		ret = clk_get_rate(&clk);
		if (!IS_ERR_VALUE(ret))
			plat->timebase_freq = ret;
	}

	return ret;
}

U_BOOT_DRIVER(cpu_bcm_drv) = {
	.name		= "bcm283x_cpu",
	.id		= UCLASS_CPU,
	.of_match	= cpu_bcm_ids,
	.ops		= &cpu_bcm_ops,
	.probe		= bcm_cpu_probe,
	.bind		= cpu_bcm_bind,
	.flags		= 0,
};
