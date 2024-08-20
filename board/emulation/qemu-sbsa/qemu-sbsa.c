/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2017 Tuomas Tynkkynen
 */

#include <config.h>
#include <cpu_func.h>
#include <dm.h>
#include <env.h>
#include <fdtdec.h>
#include <fdt_support.h>
#include <init.h>
#include <log.h>
#include <usb.h>

#include <asm/armv8/mmu.h>

/* Assigned in lowlevel_init.S
 * Push the variable into the .data section so that it
 * does not get cleared later.
 */
unsigned long __section(".data") fw_dtb_pointer;

static struct mm_region qemu_sbsa_mem_map[] = {
	{
		/* Secure flash */
		.virt = SBSA_SECURE_FLASH_BASE_ADDR,
		.phys = SBSA_SECURE_FLASH_BASE_ADDR,
		.size = SBSA_SECURE_FLASH_LENGTH,
		.attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
			 PTE_BLOCK_INNER_SHARE
	}, {
		/* Flash */
		.virt = SBSA_FLASH_BASE_ADDR,
		.phys = SBSA_FLASH_BASE_ADDR,
		.size = SBSA_FLASH_LENGTH,
		.attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
			 PTE_BLOCK_INNER_SHARE
	}, {
		/* Lowmem peripherals */
		.virt = SBSA_PERIPH_BASE_ADDR,
		.phys = SBSA_PERIPH_BASE_ADDR,
		.size = SBSA_PCIE_MMIO_BASE_ADDR - SBSA_PERIPH_BASE_ADDR,
		.attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
			 PTE_BLOCK_NON_SHARE |
			 PTE_BLOCK_PXN | PTE_BLOCK_UXN
	}, {
		/* 32-bit address PCIE MMIO space */
		.virt = SBSA_PCIE_MMIO_BASE_ADDR,
		.phys = SBSA_PCIE_MMIO_BASE_ADDR,
		.size = SBSA_PCIE_MMIO_LENGTH,
		.attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
			 PTE_BLOCK_NON_SHARE |
			 PTE_BLOCK_PXN | PTE_BLOCK_UXN
	}, {
		/* PCI-E ECAM memory area */
		.virt = SBSA_PCIE_ECAM_BASE_ADDR,
		.phys = SBSA_PCIE_ECAM_BASE_ADDR,
		.size = SBSA_PCIE_ECAM_LENGTH,
		.attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
			 PTE_BLOCK_NON_SHARE |
			 PTE_BLOCK_PXN | PTE_BLOCK_UXN
	}, {
		/* Highmem PCI-E MMIO memory area */
		.virt = SBSA_PCIE_MMIO_HIGH_BASE_ADDR,
		.phys = SBSA_PCIE_MMIO_HIGH_BASE_ADDR,
		.size = SBSA_PCIE_MMIO_HIGH_LENGTH,
		.attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
			 PTE_BLOCK_NON_SHARE |
			 PTE_BLOCK_PXN | PTE_BLOCK_UXN
	}, {
		/* DRAM */
		.virt = SBSA_MEM_BASE_ADDR,
		.phys = SBSA_MEM_BASE_ADDR,
		.size = 0x800000000000ULL,
		.attrs = PTE_BLOCK_MEMTYPE(MT_NORMAL) |
			 PTE_BLOCK_INNER_SHARE
	}, {
		/* List terminator */
		0,
	}
};

struct mm_region *mem_map = qemu_sbsa_mem_map;

int board_late_init(void)
{
	/* start usb so that usb keyboard can be used as input device */
	if (CONFIG_IS_ENABLED(USB_KEYBOARD))
		usb_init();

	return 0;
}

/*
 * If the firmware passed a device tree use it for U-Boot.
 * It only contains CPU count and usable DRAM, but no devices.
 */
void *board_fdt_blob_setup(int *err)
{
	*err = 0;

	if (fdt_magic(fw_dtb_pointer) != FDT_MAGIC) {
		*err = -ENXIO;
		return NULL;
	}
	return (void *)fw_dtb_pointer;
}

/*
 * QEMU doesn't set compatible on cpus, so add it for the CPU driver.
 */
static int fdtdec_fix_cpus(void *fdt_blob)
{
	int cpus_offset, off, ret;

	cpus_offset = fdt_path_offset(fdt_blob, "/cpus");
	if (cpus_offset < 0) {
		puts("couldn't find /cpus node\n");
		return cpus_offset;
	}

	for (off = fdt_first_subnode(fdt_blob, cpus_offset);
	     off >= 0;
	     off = fdt_next_subnode(fdt_blob, off)) {
		if (strncmp(fdt_get_name(fdt_blob, off, NULL), "cpu@", 4))
			continue;

		ret = fdt_setprop_string(fdt_blob, off, "compatible", "arm,armv8");
		if (ret < 0)
			return ret;

		ret = fdt_setprop_string(fdt_blob, off, "device_type", "cpu");
		if (ret < 0)
			return ret;
	}
	return 0;
}

/*
 * QEMU doesn't add device to FDT since it's an ACPI platform.
 * Add devices for U-Boot drivers here.
 */
static int fdtdec_add_devices(void *fdt)
{
	const char *path, *subpath;
	u32 reg32[2], range[21];
	u64 reg[2];
	int offs, ret;

	offs = fdt_increase_size(fdt, 1024);
	if (offs)
		return -ENOMEM;

	path = "/";
	offs = fdt_path_offset(fdt, path);
	if (offs < 0) {
		printf("Could not find root node.\n");
		return offs;
	}

	subpath = "soc";
	ret = fdt_add_subnode(fdt, offs, subpath);
	if (ret < 0) {
		printf("Could not create %s node.\n", subpath);
		return ret;
	}

	path = "/soc";
	offs = fdt_path_offset(fdt, path);
	if (offs < 0)
		return offs;

	ret = fdt_setprop_string(fdt, offs, "compatible", "simple-bus");
	if (ret < 0)
		return ret;

	ret = fdt_setprop_cell(fdt, offs, "#address-cells", 2);
	if (ret < 0)
		return ret;

	ret = fdt_setprop_cell(fdt, offs, "#size-cells", 2);
	if (ret < 0)
		return ret;

	ret = fdt_setprop_empty(fdt, offs, "ranges");
	if (ret < 0)
		return ret;

	subpath = "uart0";
	ret = fdt_add_subnode(fdt, offs, subpath);
	if (ret < 0) {
		printf("Could not create %s node.\n", subpath);
		return ret;
	}

	subpath = "ahci";
	ret = fdt_add_subnode(fdt, offs, subpath);
	if (ret < 0) {
		printf("Could not create %s node.\n", subpath);
		return ret;
	}

	subpath = "xhci";
	ret = fdt_add_subnode(fdt, offs, subpath);
	if (ret < 0) {
		printf("Could not create %s node.\n", subpath);
		return ret;
	}

	subpath = "pci";
	ret = fdt_add_subnode(fdt, offs, subpath);
	if (ret < 0) {
		printf("Could not create %s node.\n", subpath);
		return ret;
	}

	path = "/soc/uart0";
	offs = fdt_path_offset(fdt, path);

	ret = fdt_setprop_string(fdt, offs, "compatible", "arm,pl011");
	if (ret < 0)
		return ret;

	ret = fdt_setprop_string(fdt, offs, "status", "okay");
	if (ret < 0)
		return ret;

	reg[0] = cpu_to_fdt64((u64)SBSA_UART_BASE_ADDR);
	reg[1] = cpu_to_fdt64((u64)SBSA_UART_LENGTH);
	ret = fdt_setprop(fdt, offs, "reg", reg, sizeof(u64) * 2);
	if (ret < 0)
		return ret;

	path = "/soc/ahci";
	offs = fdt_path_offset(fdt, path);

	ret = fdt_setprop_string(fdt, offs, "compatible", "generic-ahci");
	if (ret < 0)
		return ret;

	ret = fdt_setprop_string(fdt, offs, "status", "okay");
	if (ret < 0)
		return ret;

	reg[0] = cpu_to_fdt64((u64)SBSA_AHCI_BASE_ADDR);
	reg[1] = cpu_to_fdt64((u64)SBSA_AHCI_LENGTH);
	ret = fdt_setprop(fdt, offs, "reg", reg, sizeof(u64) * 2);
	if (ret < 0)
		return ret;

	path = "/soc/xhci";
	offs = fdt_path_offset(fdt, path);

	ret = fdt_setprop_string(fdt, offs, "compatible", "generic-xhci");
	if (ret < 0)
		return ret;

	ret = fdt_setprop_string(fdt, offs, "status", "okay");
	if (ret < 0)
		return ret;

	reg[0] = cpu_to_fdt64((u64)SBSA_XHCI_BASE_ADDR);
	reg[1] = cpu_to_fdt64((u64)SBSA_XHCI_LENGTH);
	ret = fdt_setprop(fdt, offs, "reg", reg, sizeof(u64) * 2);
	if (ret < 0)
		return ret;

	path = "/soc/pci";
	offs = fdt_path_offset(fdt, path);

	ret = fdt_setprop_string(fdt, offs, "compatible", "pci-host-ecam-generic");
	if (ret < 0)
		return ret;

	ret = fdt_setprop_string(fdt, offs, "device_type", "pci");
	if (ret < 0)
		return ret;

	ret = fdt_setprop_string(fdt, offs, "status", "okay");
	if (ret < 0)
		return ret;

	reg[0] = cpu_to_fdt64((u64)SBSA_PCIE_ECAM_BASE_ADDR);
	reg[1] = cpu_to_fdt64((u64)SBSA_PCIE_ECAM_LENGTH);
	ret = fdt_setprop(fdt, offs, "reg", reg, sizeof(u64) * 2);
	if (ret < 0)
		return ret;

	reg32[0] = 0;
	reg32[1] = 0xff;
	ret = fdt_setprop(fdt, offs, "bus-range", reg32, sizeof(u32) * 2);
	if (ret < 0)
		return ret;

	ret = fdt_setprop_cell(fdt, offs, "#address-cells", 3);
	if (ret < 0)
		return ret;

	ret = fdt_setprop_cell(fdt, offs, "#size-cells", 2);
	if (ret < 0)
		return ret;

	range[0] = cpu_to_fdt32(0x01000000);
	range[1] = cpu_to_fdt32(0);
	range[2] = cpu_to_fdt32(0);
	range[3] = cpu_to_fdt32((u64)SBSA_PIO_BASE_ADDR >> 32);
	range[4] = cpu_to_fdt32((u64)SBSA_PIO_BASE_ADDR & 0xffffffff);
	range[5] = cpu_to_fdt32((u64)SBSA_PIO_LENGTH >> 32);
	range[6] = cpu_to_fdt32((u64)SBSA_PIO_LENGTH & 0xffffffff);

	range[7] = cpu_to_fdt32(0x02000000);
	range[8] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_BASE_ADDR >> 32);
	range[9] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_BASE_ADDR & 0xffffffff);
	range[10] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_BASE_ADDR >> 32);
	range[11] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_BASE_ADDR & 0xffffffff);
	range[12] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_LENGTH >> 32);
	range[13] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_LENGTH & 0xffffffff);

	range[14] = cpu_to_fdt32(0x43000000);
	range[15] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_HIGH_BASE_ADDR >> 32);
	range[16] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_HIGH_BASE_ADDR & 0xffffffff);
	range[17] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_HIGH_BASE_ADDR >> 32);
	range[18] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_HIGH_BASE_ADDR & 0xffffffff);
	range[19] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_HIGH_LENGTH >> 32);
	range[20] = cpu_to_fdt32((u64)SBSA_PCIE_MMIO_HIGH_LENGTH & 0xffffffff);

	ret = fdt_setprop(fdt, offs, "ranges", range, sizeof(range));
	if (ret < 0)
		return ret;

	return 0;
}

int fdtdec_board_setup(const void *fdt_blob)
{
	int ret;

	ret = fdtdec_fix_cpus((void *)fdt_blob);
	if (ret < 0)
		log_err("Failed to fix CPUs in FDT: %d\n", ret);

	ret = fdtdec_add_devices((void *)fdt_blob);
	if (ret < 0)
		log_err("Failed to add devices to FDT: %d\n", ret);

	return 0;
}

int board_init(void)
{
	return 0;
}

int misc_init_r(void)
{
	return env_set_hex("fdt_addr", (uintptr_t)gd->fdt_blob);
}

void reset_cpu(void)
{
}

int dram_init(void)
{
	if (fdtdec_setup_mem_size_base() != 0)
		return -EINVAL;

	return 0;
}

int dram_init_banksize(void)
{
	fdtdec_setup_memory_banksize();

	return 0;
}

void enable_caches(void)
{
	 icache_enable();
	 dcache_enable();
}

u8 flash_read8(void *addr)
{
	u8 ret;

	asm("ldrb %w0, %1" : "=r"(ret) : "m"(*(u8 *)addr));
	return ret;
}

u16 flash_read16(void *addr)
{
	u16 ret;

	asm("ldrh %w0, %1" : "=r"(ret) : "m"(*(u16 *)addr));
	return ret;
}

u32 flash_read32(void *addr)
{
	u32 ret;

	asm("ldr %w0, %1" : "=r"(ret) : "m"(*(u32 *)addr));
	return ret;
}

void flash_write8(u8 value, void *addr)
{
	asm("strb %w1, %0" : "=m"(*(u8 *)addr) : "r"(value));
}

void flash_write16(u16 value, void *addr)
{
	asm("strh %w1, %0" : "=m"(*(u16 *)addr) : "r"(value));
}

void flash_write32(u32 value, void *addr)
{
	asm("str %w1, %0" : "=m"(*(u32 *)addr) : "r"(value));
}
