// SPDX-License-Identifier: GPL-2.0+
/*
 *  EFI application ACPI tables support
 *
 *  Copyright (C) 2018, Bin Meng <bmeng.cn@gmail.com>
 */

#include <efi_loader.h>
#include <acpi/acpi_table.h>
#include <asm/global_data.h>
#include <asm/io.h>
#include <bloblist.h>
#include <linux/sizes.h>
#include <linux/log2.h>
#include <log.h>
#include <malloc.h>
#include <mapmem.h>

DECLARE_GLOBAL_DATA_PTR;

static const efi_guid_t acpi_guid = EFI_ACPI_TABLE_GUID;

enum {
	TABLE_SIZE	= SZ_64K,
};
/*
 * Install the ACPI table as a configuration table.
 *
 * Return:	status code
 */
efi_status_t efi_acpi_register(void)
{
	ulong addr, start, end;
	efi_status_t ret;

	/* Mark space used for tables */
	start = ALIGN_DOWN(gd->arch.table_start, EFI_PAGE_MASK);
	end = ALIGN(gd->arch.table_end, EFI_PAGE_MASK);
	ret = efi_add_memory_map(start, end - start, EFI_ACPI_RECLAIM_MEMORY);
	if (ret != EFI_SUCCESS)
		return ret;
	if (gd->arch.table_start_high) {
		start = ALIGN_DOWN(gd->arch.table_start_high, EFI_PAGE_MASK);
		end = ALIGN(gd->arch.table_end_high, EFI_PAGE_MASK);
		ret = efi_add_memory_map(start, end - start,
					 EFI_ACPI_RECLAIM_MEMORY);
		if (ret != EFI_SUCCESS)
			return ret;
	}

	addr = gd_acpi_start();
	log_debug("EFI using ACPI tables at %lx\n", addr);

	/* And expose them to our EFI payload */
	return efi_install_configuration_table(&acpi_guid,
					       (void *)(ulong)addr);
}

static int install_acpi_table(void)
{
	u64 rom_addr, rom_table_end;
	void *addr;

	if (!IS_ENABLED(CONFIG_GENERATE_ACPI_TABLE) ||
	    IS_ENABLED(CONFIG_X86) ||
	    IS_ENABLED(CONFIG_QFW_ACPI))
		return 0;

	/* Align the table to a 4KB boundary to keep EFI happy */
	if (IS_ENABLED(CONFIG_BLOBLIST_TABLES))
		addr = bloblist_add(BLOBLISTT_ACPI_TABLES, TABLE_SIZE,
				    ilog2(SZ_4K));
	else
		addr = memalign(SZ_4K, TABLE_SIZE);

	if (!addr)
		return log_msg_ret("mem", -ENOBUFS);

	rom_addr = virt_to_phys(addr);

	gd->arch.table_start_high = rom_addr;

	rom_table_end = write_acpi_tables(rom_addr);
	if (!rom_table_end) {
		log_err("Can't create ACPI configuration table\n");
		return -EINTR;
	}

	debug("- wrote 'acpi' to %llx, end %llx\n", rom_addr, rom_table_end);
	if (rom_table_end - rom_addr > TABLE_SIZE) {
		log_err("Out of space for configuration tables: need %llx, have %x\n",
			rom_table_end - rom_addr, TABLE_SIZE);
		return log_msg_ret("acpi", -ENOSPC);
	}
	gd->arch.table_end_high = rom_table_end;

	debug("- done writing tables\n");

	return 0;
}

EVENT_SPY_SIMPLE(EVT_LAST_STAGE_INIT, install_acpi_table);
