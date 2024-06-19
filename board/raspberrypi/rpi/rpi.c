// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2012-2016 Stephen Warren
 */

#define LOG_CATEGORY LOGC_BOARD

#include <common.h>
#include <config.h>
#include <dm.h>
#include <env.h>
#include <efi_loader.h>
#include <fdt_support.h>
#include <fdt_simplefb.h>
#include <init.h>
#include <log.h>
#include <memalign.h>
#include <mmc.h>
#include <signatures.h>
#include <tables_csum.h>
#include <acpi/acpi_table.h>
#include <asm/acpi_table.h>
#include <asm/global_data.h>
#include <asm/gpio.h>
#include <asm/arch/mbox.h>
#include <asm/arch/msg.h>
#include <asm/arch/sdhci.h>
#include <asm/arch/acpi/bcm2836.h>
#include <dm/acpi.h>
#include <dm/platform_data/serial_bcm283x_mu.h>
#ifdef CONFIG_ARM64
#include <asm/armv8/mmu.h>
#endif
#include <watchdog.h>
#include <dm/pinctrl.h>
#ifdef CONFIG_GENERATE_ACPI_TABLE
#include "acpitables.h"
#endif

DECLARE_GLOBAL_DATA_PTR;

/* Assigned in lowlevel_init.S
 * Push the variable into the .data section so that it
 * does not get cleared later.
 */
unsigned long __section(".data") fw_dtb_pointer;

/* TODO(sjg@chromium.org): Move these to the msg.c file */
struct msg_get_arm_mem {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_arm_mem get_arm_mem;
	u32 end_tag;
};

struct msg_get_board_rev {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_board_rev get_board_rev;
	u32 end_tag;
};

struct msg_get_board_serial {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_board_serial get_board_serial;
	u32 end_tag;
};

struct msg_get_mac_address {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_mac_address get_mac_address;
	u32 end_tag;
};

struct msg_get_clock_rate {
	struct bcm2835_mbox_hdr hdr;
	struct bcm2835_mbox_tag_get_clock_rate get_clock_rate;
	u32 end_tag;
};

#ifdef CONFIG_ARM64
#define DTB_DIR "broadcom/"
#else
#define DTB_DIR ""
#endif

/*
 * https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#raspberry-pi-revision-codes
 */
struct rpi_model {
	const char *name;
	const char *fdtfile;
	bool has_onboard_eth;
};

static const struct rpi_model rpi_model_unknown = {
	"Unknown model",
	DTB_DIR "bcm283x-rpi-other.dtb",
	false,
};

static const struct rpi_model rpi_models_new_scheme[] = {
	[0x0] = {
		"Model A",
		DTB_DIR "bcm2835-rpi-a.dtb",
		false,
	},
	[0x1] = {
		"Model B",
		DTB_DIR "bcm2835-rpi-b.dtb",
		true,
	},
	[0x2] = {
		"Model A+",
		DTB_DIR "bcm2835-rpi-a-plus.dtb",
		false,
	},
	[0x3] = {
		"Model B+",
		DTB_DIR "bcm2835-rpi-b-plus.dtb",
		true,
	},
	[0x4] = {
		"2 Model B",
		DTB_DIR "bcm2836-rpi-2-b.dtb",
		true,
	},
	[0x6] = {
		"Compute Module",
		DTB_DIR "bcm2835-rpi-cm.dtb",
		false,
	},
	[0x8] = {
		"3 Model B",
		DTB_DIR "bcm2837-rpi-3-b.dtb",
		true,
	},
	[0x9] = {
		"Zero",
		DTB_DIR "bcm2835-rpi-zero.dtb",
		false,
	},
	[0xA] = {
		"Compute Module 3",
		DTB_DIR "bcm2837-rpi-cm3.dtb",
		false,
	},
	[0xC] = {
		"Zero W",
		DTB_DIR "bcm2835-rpi-zero-w.dtb",
		false,
	},
	[0xD] = {
		"3 Model B+",
		DTB_DIR "bcm2837-rpi-3-b-plus.dtb",
		true,
	},
	[0xE] = {
		"3 Model A+",
		DTB_DIR "bcm2837-rpi-3-a-plus.dtb",
		false,
	},
	[0x10] = {
		"Compute Module 3+",
		DTB_DIR "bcm2837-rpi-cm3.dtb",
		false,
	},
	[0x11] = {
		"4 Model B",
		DTB_DIR "bcm2711-rpi-4-b.dtb",
		true,
	},
	[0x12] = {
		"Zero 2 W",
		DTB_DIR "bcm2837-rpi-zero-2-w.dtb",
		false,
	},
	[0x13] = {
		"400",
		DTB_DIR "bcm2711-rpi-400.dtb",
		true,
	},
	[0x14] = {
		"Compute Module 4",
		DTB_DIR "bcm2711-rpi-cm4.dtb",
		true,
	},
	[0x17] = {
		"5 Model B",
		DTB_DIR "bcm2712-rpi-5-b.dtb",
		true,
	},
};

static const struct rpi_model rpi_models_old_scheme[] = {
	[0x2] = {
		"Model B",
		DTB_DIR "bcm2835-rpi-b.dtb",
		true,
	},
	[0x3] = {
		"Model B",
		DTB_DIR "bcm2835-rpi-b.dtb",
		true,
	},
	[0x4] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0x5] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0x6] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0x7] = {
		"Model A",
		DTB_DIR "bcm2835-rpi-a.dtb",
		false,
	},
	[0x8] = {
		"Model A",
		DTB_DIR "bcm2835-rpi-a.dtb",
		false,
	},
	[0x9] = {
		"Model A",
		DTB_DIR "bcm2835-rpi-a.dtb",
		false,
	},
	[0xd] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0xe] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0xf] = {
		"Model B rev2",
		DTB_DIR "bcm2835-rpi-b-rev2.dtb",
		true,
	},
	[0x10] = {
		"Model B+",
		DTB_DIR "bcm2835-rpi-b-plus.dtb",
		true,
	},
	[0x11] = {
		"Compute Module",
		DTB_DIR "bcm2835-rpi-cm.dtb",
		false,
	},
	[0x12] = {
		"Model A+",
		DTB_DIR "bcm2835-rpi-a-plus.dtb",
		false,
	},
	[0x13] = {
		"Model B+",
		DTB_DIR "bcm2835-rpi-b-plus.dtb",
		true,
	},
	[0x14] = {
		"Compute Module",
		DTB_DIR "bcm2835-rpi-cm.dtb",
		false,
	},
	[0x15] = {
		"Model A+",
		DTB_DIR "bcm2835-rpi-a-plus.dtb",
		false,
	},
};

static uint32_t revision;
static uint32_t rev_scheme;
static uint32_t rev_type;
static const struct rpi_model *model;

int dram_init(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct msg_get_arm_mem, msg, 1);
	int ret;

	BCM2835_MBOX_INIT_HDR(msg);
	BCM2835_MBOX_INIT_TAG(&msg->get_arm_mem, GET_ARM_MEMORY);

	ret = bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr);
	if (ret) {
		printf("bcm2835: Could not query ARM memory size\n");
		return -1;
	}

	gd->ram_size = msg->get_arm_mem.body.resp.mem_size;

	/*
	 * In some configurations the memory size returned by VideoCore
	 * is not aligned to the section size, what is mandatory for
	 * the u-boot's memory setup.
	 */
	gd->ram_size &= ~MMU_SECTION_SIZE;

	return 0;
}

#ifdef CONFIG_OF_BOARD
int dram_init_banksize(void)
{
	int ret;

	ret = fdtdec_setup_memory_banksize();
	if (ret)
		return ret;

	return fdtdec_setup_mem_size_base();
}
#endif

static void set_fdtfile(void)
{
	const char *fdtfile;

	if (env_get("fdtfile"))
		return;

	fdtfile = model->fdtfile;
	env_set("fdtfile", fdtfile);
}

/*
 * If the firmware provided a valid FDT at boot time, let's expose it in
 * ${fdt_addr} so it may be passed unmodified to the kernel.
 */
static void set_fdt_addr(void)
{
	if (env_get("fdt_addr"))
		return;

	if (fdt_magic(fw_dtb_pointer) != FDT_MAGIC)
		return;

	env_set_hex("fdt_addr", fw_dtb_pointer);
}

/*
 * Prevent relocation from stomping on a firmware provided FDT blob.
 */
phys_addr_t board_get_usable_ram_top(phys_size_t total_size)
{
	if ((gd->ram_top - fw_dtb_pointer) > SZ_64M)
		return gd->ram_top;
	return fw_dtb_pointer & ~0xffff;
}

static void set_usbethaddr(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct msg_get_mac_address, msg, 1);
	int ret;

	if (!model->has_onboard_eth)
		return;

	if (env_get("usbethaddr"))
		return;

	BCM2835_MBOX_INIT_HDR(msg);
	BCM2835_MBOX_INIT_TAG(&msg->get_mac_address, GET_MAC_ADDRESS);

	ret = bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr);
	if (ret) {
		printf("bcm2835: Could not query MAC address\n");
		/* Ignore error; not critical */
		return;
	}

	eth_env_set_enetaddr("usbethaddr", msg->get_mac_address.body.resp.mac);

	if (!env_get("ethaddr"))
		env_set("ethaddr", env_get("usbethaddr"));

	return;
}

#ifdef CONFIG_ENV_VARS_UBOOT_RUNTIME_CONFIG
static void set_board_info(void)
{
	char s[11];

	snprintf(s, sizeof(s), "0x%X", revision);
	env_set("board_revision", s);
	snprintf(s, sizeof(s), "%d", rev_scheme);
	env_set("board_rev_scheme", s);
	/* Can't rename this to board_rev_type since it's an ABI for scripts */
	snprintf(s, sizeof(s), "0x%X", rev_type);
	env_set("board_rev", s);
	env_set("board_name", model->name);
}
#endif /* CONFIG_ENV_VARS_UBOOT_RUNTIME_CONFIG */

static void set_serial_number(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct msg_get_board_serial, msg, 1);
	int ret;
	char serial_string[17] = { 0 };

	if (env_get("serial#"))
		return;

	BCM2835_MBOX_INIT_HDR(msg);
	BCM2835_MBOX_INIT_TAG_NO_REQ(&msg->get_board_serial, GET_BOARD_SERIAL);

	ret = bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr);
	if (ret) {
		printf("bcm2835: Could not query board serial\n");
		/* Ignore error; not critical */
		return;
	}

	snprintf(serial_string, sizeof(serial_string), "%016llx",
		 msg->get_board_serial.body.resp.serial);
	env_set("serial#", serial_string);
}

int misc_init_r(void)
{
	set_fdt_addr();
	set_fdtfile();
	set_usbethaddr();
#ifdef CONFIG_ENV_VARS_UBOOT_RUNTIME_CONFIG
	set_board_info();
#endif
	set_serial_number();

	return 0;
}

static void get_board_revision(void)
{
	ALLOC_CACHE_ALIGN_BUFFER(struct msg_get_board_rev, msg, 1);
	int ret;
	const struct rpi_model *models;
	uint32_t models_count;
	ofnode node;

	BCM2835_MBOX_INIT_HDR(msg);
	BCM2835_MBOX_INIT_TAG(&msg->get_board_rev, GET_BOARD_REV);

	ret = bcm2835_mbox_call_prop(BCM2835_MBOX_PROP_CHAN, &msg->hdr);
	if (ret) {
		/* Ignore error; not critical */
		node = ofnode_path("/system");
		if (!ofnode_valid(node)) {
			printf("bcm2835: Could not find /system node\n");
			return;
		}

		ret = ofnode_read_u32(node, "linux,revision", &revision);
		if (ret) {
			printf("bcm2835: Could not find linux,revision\n");
			return;
		}
	} else {
		revision = msg->get_board_rev.body.resp.rev;
	}

	/*
	 * For details of old-vs-new scheme, see:
	 * https://github.com/pimoroni/RPi.version/blob/master/RPi/version.py
	 * http://www.raspberrypi.org/forums/viewtopic.php?f=63&t=99293&p=690282
	 * (a few posts down)
	 *
	 * For the RPi 1, bit 24 is the "warranty bit", so we mask off just the
	 * lower byte to use as the board rev:
	 * http://www.raspberrypi.org/forums/viewtopic.php?f=63&t=98367&start=250
	 * http://www.raspberrypi.org/forums/viewtopic.php?f=31&t=20594
	 */
	if (revision & 0x800000) {
		rev_scheme = 1;
		rev_type = (revision >> 4) & 0xff;
		models = rpi_models_new_scheme;
		models_count = ARRAY_SIZE(rpi_models_new_scheme);
	} else {
		rev_scheme = 0;
		rev_type = revision & 0xff;
		models = rpi_models_old_scheme;
		models_count = ARRAY_SIZE(rpi_models_old_scheme);
	}
	if (rev_type >= models_count) {
		printf("RPI: Board rev 0x%x outside known range\n", rev_type);
		model = &rpi_model_unknown;
	} else if (!models[rev_type].name) {
		printf("RPI: Board rev 0x%x unknown\n", rev_type);
		model = &rpi_model_unknown;
	} else {
		model = &models[rev_type];
	}

	printf("RPI %s (0x%x)\n", model->name, revision);
}

int board_init(void)
{
#ifdef CONFIG_HW_WATCHDOG
	hw_watchdog_init();
#endif

	get_board_revision();

	gd->bd->bi_boot_params = 0x100;

	return bcm2835_power_on_module(BCM2835_MBOX_POWER_DEVID_USB_HCD);
}

/*
 * If the firmware passed a device tree use it for U-Boot.
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

int copy_property(void *dst, void *src, char *path, char *property)
{
	int dst_offset, src_offset;
	const fdt32_t *prop;
	int len;

	src_offset = fdt_path_offset(src, path);
	dst_offset = fdt_path_offset(dst, path);

	if (src_offset < 0 || dst_offset < 0)
		return -1;

	prop = fdt_getprop(src, src_offset, property, &len);
	if (!prop)
		return -1;

	return fdt_setprop(dst, dst_offset, property, prop, len);
}

/* Copy tweaks from the firmware dtb to the loaded dtb */
void  update_fdt_from_fw(void *fdt, void *fw_fdt)
{
	/* Using dtb from firmware directly; leave it alone */
	if (fdt == fw_fdt)
		return;

	/* The firmware provides a more precie model; so copy that */
	copy_property(fdt, fw_fdt, "/", "model");

	/* memory reserve as suggested by the firmware */
	copy_property(fdt, fw_fdt, "/", "memreserve");

	/* Adjust dma-ranges for the SD card and PCI bus as they can depend on
	 * the SoC revision
	 */
	copy_property(fdt, fw_fdt, "emmc2bus", "dma-ranges");
	copy_property(fdt, fw_fdt, "pcie0", "dma-ranges");

	/* Bootloader configuration template exposes as nvmem */
	if (copy_property(fdt, fw_fdt, "blconfig", "reg") == 0)
		copy_property(fdt, fw_fdt, "blconfig", "status");

	/* kernel address randomisation seed as provided by the firmware */
	copy_property(fdt, fw_fdt, "/chosen", "kaslr-seed");

	/* address of the PHY device as provided by the firmware  */
	copy_property(fdt, fw_fdt, "ethernet0/mdio@e14/ethernet-phy@1", "reg");
}

int ft_board_setup(void *blob, struct bd_info *bd)
{
	int node;

	update_fdt_from_fw(blob, (void *)fw_dtb_pointer);

	node = fdt_node_offset_by_compatible(blob, -1, "simple-framebuffer");
	if (node < 0)
		fdt_simplefb_add_node(blob);
	else
		fdt_simplefb_enable_and_mem_rsv(blob);

#ifdef CONFIG_EFI_LOADER
	/* Reserve the spin table */
	efi_add_memory_map(0, CONFIG_RPI_EFI_NR_SPIN_PAGES << EFI_PAGE_SHIFT,
			   EFI_RESERVED_MEMORY_TYPE);
#endif

	return 0;
}

#ifdef CONFIG_GENERATE_ACPI_TABLE
int last_stage_init(void)
{
	int ret;

	ret = write_acpi_tables(0x10000);
	if (ret < 0) {
		log_err("Failed to write tables\n");
		return log_msg_ret("table", ret);
	}

	return 0;
}
EVENT_SPY_SIMPLE(EVT_LAST_STAGE_INIT, last_stage_init);

static int rpi_write_facp(struct acpi_ctx *ctx, const struct acpi_writer *entry)
{
	struct acpi_table_header *header;
	struct acpi_fadt *fadt;

	fadt = ctx->current;
	header = &fadt->header;

	memset(fadt, '\0', sizeof(struct acpi_fadt));

	acpi_fill_header(header, "FACP");
	header->length = sizeof(struct acpi_fadt);
	header->revision = ACPI_FADT_REV_ACPI_6_0;

	fadt->firmware_ctrl = (ulong)ctx->facs;
	fadt->dsdt = (ulong)ctx->dsdt;
	fadt->preferred_pm_profile = ACPI_PM_APPLIANCE_PC;

	fadt->flags = ACPI_FADT_WBINVD | ACPI_FADT_SLEEP_BUTTON |
		ACPI_FADT_HW_REDUCED_ACPI;
	fadt->arm_boot_arch = ACPI_ARM_PSCI_COMPLIANT;
	fadt->minor_revision = 3;

	fadt->x_firmware_ctrl = (ulong)ctx->facs;
	fadt->x_dsdt = (ulong)ctx->dsdt;

	header->checksum = table_compute_checksum(fadt, header->length);

	acpi_add_table(ctx, fadt);

	acpi_inc(ctx, sizeof(struct acpi_fadt));

	return 0;
}
ACPI_WRITER(5facp, "FACP", rpi_write_facp, 0);

#define GTDT_FLAG_INT_ACTIVE_LOW	BIT(1)
#define RPI_GTDT_GTIMER_FLAGS		GTDT_FLAG_INT_ACTIVE_LOW

/* ARM Architectural Timer Interrupt(GIC PPI) numbers */
#define PcdArmArchTimerSecIntrNum	29
#define PcdArmArchTimerIntrNum		30
#define PcdArmArchTimerHypIntrNum	26
#define PcdArmArchTimerVirtIntrNum	27

static int rpi_write_gtdt(struct acpi_ctx *ctx, const struct acpi_writer *entry)
{
	struct acpi_table_header *header;
	struct acpi_gtdt *gtdt;

	gtdt = ctx->current;
	header = &gtdt->header;

	memset(gtdt, '\0', sizeof(struct acpi_gtdt));

	acpi_fill_header(header, "GTDT");
	header->length = sizeof(struct acpi_gtdt);
	header->revision = 3;

	gtdt->cnt_ctrl_base = RPI_SYSTEM_TIMER_BASE_ADDRESS;
	gtdt->sec_el1_gsiv = PcdArmArchTimerSecIntrNum;
	gtdt->sec_el1_flags = RPI_GTDT_GTIMER_FLAGS;
	gtdt->el1_gsiv = PcdArmArchTimerIntrNum;
	gtdt->el1_flags = RPI_GTDT_GTIMER_FLAGS;
	gtdt->virt_el1_gsiv = PcdArmArchTimerVirtIntrNum;
	gtdt->virt_el1_flags = RPI_GTDT_GTIMER_FLAGS;
	gtdt->el2_gsiv = PcdArmArchTimerHypIntrNum;
	gtdt->el2_flags = RPI_GTDT_GTIMER_FLAGS;
	gtdt->cnt_read_base = 0xffffffffffffffff;
	acpi_add_table(ctx, gtdt);

	acpi_inc(ctx, sizeof(struct acpi_gtdt));

	return 0;
};
ACPI_WRITER(5gtdt, "GTDT", rpi_write_gtdt, 0);

static int rpi_write_dbg2(struct acpi_ctx *ctx, const struct acpi_writer *entry)
{
	struct acpi_table_header *header;
	struct acpi_dbg2_header *dbg2;
	struct acpi_dbg2_device *ddev;
	struct acpi_gen_regaddr *addr;
	u32 *addr_size;
	char *name;
	void *end;

	dbg2 = ctx->current;
	header = &dbg2->header;

	/* Note this doesn't zero everything */
	memset(dbg2, '\0', sizeof(struct acpi_dbg2_header));

	acpi_fill_header(header, "DBG2");
	header->revision = 0;

	dbg2->devices_offset = sizeof(*dbg2);
	dbg2->devices_count = 1;

	ddev = (void *)(dbg2 + 1);
	ddev->revision = 0;
	ddev->length = 0x35;
	ddev->address_count = 1;
	ddev->namespace_string_length = 0xf;
	ddev->namespace_string_offset = 0x26;
	ddev->oem_data_length = 0;
	ddev->oem_data_offset = 0;
	ddev->port_type = ACPI_DBG2_SERIAL_PORT;
	ddev->port_subtype = ACPI_DBG2_ARM_PL011;

	addr = (void *)(ddev + 1);
	ddev->base_address_offset = sizeof(*ddev);
	ddev->address_size_offset = sizeof(*ddev) + sizeof(*addr);

	addr->space_id = ACPI_ADDRESS_SPACE_MEMORY;
	addr->bit_width = 32;
	addr->bit_offset = 0;
	addr->access_size = ACPI_ACCESS_SIZE_DWORD_ACCESS;
	addr->addrl = 0xfe201000;
	addr->addrh = 0;

	addr_size = (u32 *)(addr + 1);
	*addr_size = 0x1000;

	name = (char *)(addr_size + 1);
	strcpy(name, "\\_SB.GDV0.URT0");
	end = name + strlen(name) + 1;
	header->length = end - ctx->current;
	acpi_add_table(ctx, dbg2);

	acpi_inc(ctx, header->length);

	return 0;
};
ACPI_WRITER(5dbg2, "DBG2", rpi_write_dbg2, 0);

#if 0
/* Need to add a logo first */
static int rpi_write_bgrt(struct acpi_ctx *ctx, const struct acpi_writer *entry)
{
	struct acpi_table_header *header;
	struct acpi_bgrt_header *bgrt;

	bgrt = ctx->current;
	header = &dbg2->header;

	memset(bgrt, '\0', sizeof(struct acpi_bgrt));

	acpi_fill_header(header, "BGRT");
	header->revision = 0;

	acpi_inc(ctx, header->length);

	return 0;
};
ACPI_WRITER(5bgrt, "BGRT", rpi_write_bgrt, 0);
#endif

static u32 *add_proc(struct acpi_ctx *ctx, int flags, int parent, int proc_id,
		     int num_resources)
{
	struct acpi_pptt_proc *proc = ctx->current;
	u32 *resource_list;

	proc->hdr.type = ACPI_PPTT_TYPE_PROC;
	proc->flags = flags;
	proc->parent = parent;
	proc->proc_id = proc_id;
	proc->num_resources = num_resources;
	proc->hdr.length = sizeof(struct acpi_pptt_proc) +
		sizeof(u32) * num_resources;
	resource_list = ctx->current + sizeof(struct acpi_pptt_proc);
	acpi_inc(ctx, proc->hdr.length);

	return resource_list;
}

static int add_cache(struct acpi_ctx *ctx, int flags, int size, int sets,
		     int assoc, int attributes, int line_size)
{
	struct acpi_pptt_cache *cache = ctx->current;
	int ofs;

	ofs = ctx->current - ctx->tab_start;
	cache->hdr.type = ACPI_PPTT_TYPE_CACHE;
	cache->hdr.length = sizeof(struct acpi_pptt_cache);
	cache->flags = flags;
	cache->next_cache_level = 0;
	cache->size = size;
	cache->sets = sets;
	cache->assoc = assoc;
	cache->attributes = attributes;
	cache->line_size = line_size;
	acpi_inc(ctx, cache->hdr.length);

	return ofs;
}

static int rpi_write_pptt(struct acpi_ctx *ctx, const struct acpi_writer *entry)
{
	struct acpi_table_header *header;
	int proc_ofs;
	u32 *proc_ptr;
	int ofs, ofs0, ofs1, i;

	header = ctx->current;
	ctx->tab_start = ctx->current;

	memset(header, '\0', sizeof(struct acpi_table_header));

	acpi_fill_header(header, "PPTT");
	header->revision = 0;
	acpi_inc(ctx, sizeof(*header));

	proc_ofs = ctx->current - ctx->tab_start;
	proc_ptr = add_proc(ctx, ACPI_PPTT_PHYSICAL_PACKAGE |
			    ACPI_PPTT_CHILDREN_IDENTICAL, 0, 0, 1);

	ofs = add_cache(ctx, ACPI_PPTT_ALL_VALID, 0x100000, 0x400, 0x10,
			ACPI_PPTT_WRITE_ALLOC |
			(ACPI_PPTT_CACHE_TYPE_UNIFIED <<
			 ACPI_PPTT_CACHE_TYPE_SHIFT), 0x40);
	*proc_ptr = ofs;

	for (i = 0; i < 4; i++) {
		proc_ptr = add_proc(ctx, ACPI_PPTT_CHILDREN_IDENTICAL |
				    ACPI_PPTT_NODE_IS_LEAF | ACPI_PPTT_PROC_ID_VALID,
				    proc_ofs, i, 2);

		ofs0 = add_cache(ctx, ACPI_PPTT_ALL_VALID, 0x8000, 0x100, 2,
				 ACPI_PPTT_WRITE_ALLOC, 0x40);

		ofs1 = add_cache(ctx, ACPI_PPTT_ALL_BUT_WRITE_POL, 0xc000, 0x100, 3,
				 ACPI_PPTT_CACHE_TYPE_INSTR <<
				 ACPI_PPTT_CACHE_TYPE_SHIFT, 0x40);
		proc_ptr[0] = ofs0;
		proc_ptr[1] = ofs1;
	}

	header->length = ctx->current - ctx->tab_start;
	header->checksum = table_compute_checksum(header, header->length);

	acpi_inc(ctx, header->length);
	acpi_add_table(ctx, header);

	return 0;
};
ACPI_WRITER(5pptt, "PPTT", rpi_write_pptt, 0);

static void acpi_write_madt_gicc(struct acpi_ctx *ctx, uint cpu_num,
				 uint perf_gsiv, ulong phys_base, ulong gicv,
				 ulong gich, uint vgic_maint_irq, ulong mpidr,
				 uint efficiency)
{
	struct acpi_madr_gicc *gicc = ctx->current;

	memset(gicc, '\0', sizeof(struct acpi_madr_gicc));
	gicc->type = ACPI_APIC_GICC;
	gicc->length = sizeof(struct acpi_madr_gicc);
	gicc->cpu_if_num = cpu_num;
	gicc->processor_id = cpu_num;
	gicc->flags = ACPI_MADRF_ENABLED;
	gicc->perf_gsiv = perf_gsiv;
	gicc->phys_base = phys_base;
	gicc->gicv = gicv;
	gicc->gich = gich;
	gicc->vgic_maint_irq = vgic_maint_irq;
	gicc->mpidr = mpidr;
	gicc->efficiency = efficiency;
	acpi_inc(ctx, gicc->length);
}

static void acpi_write_madt_gicd(struct acpi_ctx *ctx, uint gic_id,
				 ulong phys_base, uint gic_version)
{
	struct acpi_madr_gicd *gicd = ctx->current;

	memset(gicd, '\0', sizeof(struct acpi_madr_gicd));
	gicd->type = ACPI_APIC_GICD;
	gicd->length = sizeof(struct acpi_madr_gicd);
	gicd->gic_id = gic_id;
	gicd->phys_base = phys_base;
	gicd->gic_version = gic_version;

	acpi_inc(ctx, gicd->length);
}

static int rpi_write_madt(struct acpi_ctx *ctx, const struct acpi_writer *entry)
{
	struct acpi_table_header *header;
	struct acpi_madt *madt;
	int i;

	ctx->tab_start = ctx->current;
	madt = ctx->current;

	memset(madt, '\0', sizeof(struct acpi_madt));
	header = &madt->header;

	/* Fill out header fields */
	acpi_fill_header(header, "APIC");
	header->length = sizeof(struct acpi_madt);
	header->revision = ACPI_MADT_REV_ACPI_6_0;

	madt->lapic_addr = 0;
	madt->flags = 0;
	acpi_inc(ctx, sizeof(*madt));

	for (i = 0; i < 4; i++) {
		acpi_write_madt_gicc(ctx, i, 0x30 + i, 0xff842000, 0xff846000,
				     0xff844000, 0x19, i, 1);
	}
	acpi_write_madt_gicd(ctx, 0, 0xff841000, 2);

	/* (Re)calculate length and checksum */
	header->length = (u32)(ctx->current - ctx->tab_start);

	header->checksum = table_compute_checksum((void *)madt, header->length);
	acpi_add_table(ctx, madt);
	acpi_inc(ctx, madt->header.length);

	return 0;
}
ACPI_WRITER(5madt, "APIC", rpi_write_madt, 0);

/* DMA Controller Vendor Data */
struct __packed dma_ctlr_vendor_data {
	u32 length;
	u32 type;
	u64 chan_base;
	u32 chan_size;
	u64 ctlr_base;
	u32 ctlr_size;
	u32 chan_count;
	u32 ctlr_irq;
	u32 min_req_line;
	u32 max_req_line;
	u8 cache_coherent;
};

/* DMA Controller */
struct __packed rd_dma_ctlr {
	struct acpi_csrt_descriptor hdr;
	struct dma_ctlr_vendor_data data;
};

/* dma chan vendor data */
struct __packed dma_chan_vendor_data {
	u32 chan;
	u32 chan_irq;
	u16 is_reserved;
	u16 addr_incr;
};

/* dma chan */
struct __packed rd_dma_chan {
	struct acpi_csrt_descriptor hdr;
	struct dma_chan_vendor_data data;
};

/* dma resource group */
struct __packed rg_dma {
	struct acpi_csrt_group hdr;
	struct rd_dma_ctlr ctlr;
	struct rd_dma_chan chan[];
};

#define RPI_DMA_MAX_REQ_LINES 32

static void add_cmd_chan(struct rd_dma_chan *dmac, uint uid, uint chan,
			 uint chan_irq, bool is_reserved, int addr_incr)
{
	memset(dmac, '\0', sizeof(*dmac));
	dmac->hdr.length = sizeof(struct rd_dma_chan);
	dmac->hdr.type = EFI_ACPI_CSRT_RESOURCE_TYPE_DMA;
	dmac->hdr.subtype = EFI_ACPI_CSRT_RESOURCE_SUBTYPE_DMA_CHANNEL;
	dmac->hdr.uid = uid;

	dmac->data.chan = chan;
	dmac->data.chan_irq = chan_irq;
	dmac->data.is_reserved = is_reserved;
	dmac->data.addr_incr = addr_incr;
}

int acpi_fill_csrt(struct acpi_ctx *ctx)
{
	struct dma_ctlr_vendor_data *data;
	struct acpi_csrt_group *hdr;
	struct rg_dma *dma;
	int i;

	dma = ctx->current;
	hdr = &dma->hdr;
	memset(hdr, '\0', sizeof(*hdr));
	hdr->length = 0;
	hdr->vendor_id = SIGNATURE_32('R', 'P', 'I', 'F');
	hdr->device_id = EFI_ACPI_CSRT_DEVICE_ID_DMA;

	dma->ctlr.hdr.length = sizeof(struct rd_dma_ctlr);
	dma->ctlr.hdr.type = EFI_ACPI_CSRT_RESOURCE_TYPE_DMA;
	dma->ctlr.hdr.subtype = EFI_ACPI_CSRT_RESOURCE_SUBTYPE_DMA_CONTROLLER;
	dma->ctlr.hdr.uid = EFI_ACPI_CSRT_RESOURCE_ID_IN_DMA_GRP;

	data = &dma->ctlr.data;
	data->length = sizeof(struct dma_ctlr_vendor_data);
	data->type = 1;
	data->chan_base = BCM2836_DMA0_BASE_ADDRESS;
	data->chan_size = RPI_DMA_CHANNEL_COUNT * BCM2836_DMA_CHANNEL_LENGTH;
	data->ctlr_base = BCM2836_DMA_CTRL_BASE_ADDRESS;
	data->ctlr_size = 8;
	data->chan_count = RPI_DMA_USED_CHANNEL_COUNT;
	data->max_req_line = RPI_DMA_MAX_REQ_LINES - 1;

	acpi_inc(ctx, sizeof(struct rg_dma));

	for (i = 0; i < 10; i++) {
		add_cmd_chan(&dma->chan[i],
			     EFI_ACPI_CSRT_RESOURCE_ID_IN_DMA_GRP + 1 + i, i,
			     0x30 + i,
			     i == 1 || i == 2 || i == 3 || i == 6 || i == 7,
			     i == 4);
		acpi_inc(ctx, sizeof(struct rd_dma_chan));
	}

	hdr->length = (u32)(ctx->current - (void *)dma);

	return 0;
}
#endif
