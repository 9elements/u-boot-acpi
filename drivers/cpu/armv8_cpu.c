// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2019 Broadcom.
 */
#include <acpi/acpigen.h>
#include <asm/armv8/cpu.h>
#include <cpu.h>
#include <dm.h>
#include <dm/acpi.h>
#include <asm/io.h>
#include <linux/bitops.h>
#include <linux/printk.h>
#include <linux/sizes.h>

static int armv8_cpu_get_desc(const struct udevice *dev, char *buf, int size)
{
	int cpuid;

	cpuid = (read_midr() & MIDR_PARTNUM_MASK) >> MIDR_PARTNUM_SHIFT;

	snprintf(buf, size, "CPU MIDR %04x", cpuid);

	return 0;
}

static int armv8_cpu_get_info(const struct udevice *dev,
			      struct cpu_info *info)
{
	info->cpu_freq = 0;
	info->features = BIT(CPU_FEAT_L1_CACHE) | BIT(CPU_FEAT_MMU);

	return 0;
}

static int armv8_cpu_get_count(const struct udevice *dev)
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

#ifdef CONFIG_ACPIGEN
static int acpi_cpu_fill_ssdt(const struct udevice *dev, struct acpi_ctx *ctx)
{
	uint core_id = dev_seq(dev);

	acpigen_write_processor_device(ctx, core_id);

	return 0;
}

struct acpi_ops armv8_cpu_acpi_ops = {
	.fill_ssdt	= acpi_cpu_fill_ssdt,
};
#endif

static const struct cpu_ops cpu_ops = {
	.get_count = armv8_cpu_get_count,
	.get_desc  = armv8_cpu_get_desc,
	.get_info  = armv8_cpu_get_info,
};

static const struct udevice_id cpu_ids[] = {
	{ .compatible = "arm,armv8" },
	{}
};

U_BOOT_DRIVER(arm_cpu) = {
	.name		= "arm-cpu",
	.id		= UCLASS_CPU,
	.of_match	= cpu_ids,
	.ops		= &cpu_ops,
	.flags		= DM_FLAG_PRE_RELOC,
	ACPI_OPS_PTR(&armv8_cpu_acpi_ops)
};
