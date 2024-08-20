// SPDX-License-Identifier: GPL-2.0+
/*
 *  EFI application ACPI tables support
 *
 *  Copyright (C) 2018, Bin Meng <bmeng.cn@gmail.com>
 */

#include <efi_loader.h>
#include <bloblist.h>
#include <log.h>
#include <malloc.h>
#include <mapmem.h>
#include <acpi/acpi_table.h>
#include <asm/global_data.h>
#include <asm/io.h>
#include <linux/sizes.h>
#include <linux/log2.h>

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

/*
 * Allocate memory for ACPI tables and write ACPI tables to the
 * allocated buffer.
 *
 * Return:	status code
 */
static int alloc_write_acpi_tables(void)
{
	u64 table_addr, table_end;
	u64 new_acpi_addr = 0;
	efi_uintn_t pages;
	efi_status_t ret;
	void *addr;

	if (!IS_ENABLED(CONFIG_GENERATE_ACPI_TABLE))
		return 0;

	if (IS_ENABLED(CONFIG_X86) ||
	    IS_ENABLED(CONFIG_QFW_ACPI) ||
	    IS_ENABLED(CONFIG_SANDBOX)) {
		log_debug("Skipping writing ACPI tables as already done\n");
		return 0;
	}

	/* Align the table to a 4KB boundary to keep EFI happy */
	if (IS_ENABLED(CONFIG_BLOBLIST_TABLES)) {
		addr = bloblist_add(BLOBLISTT_ACPI_TABLES, TABLE_SIZE,
				    ilog2(SZ_4K));

		if (!addr)
			return log_msg_ret("mem", -ENOMEM);
	} else {
		pages = efi_size_in_pages(TABLE_SIZE);

		ret = efi_allocate_pages(EFI_ALLOCATE_ANY_PAGES,
					 EFI_ACPI_RECLAIM_MEMORY,
					 pages, &new_acpi_addr);
		if (ret != EFI_SUCCESS)
			return log_msg_ret("mem", -ENOMEM);

		addr = (void *)(uintptr_t)new_acpi_addr;
	}

	table_addr = virt_to_phys(addr);

	gd->arch.table_start_high = table_addr;

	table_end = write_acpi_tables(table_addr);
	if (!table_end) {
		log_err("Can't create ACPI configuration table\n");
		return -EINTR;
	}

	log_debug("- wrote 'acpi' to %llx, end %llx\n", table_addr, table_end);
	if (table_end - table_addr > TABLE_SIZE) {
		log_err("Out of space for configuration tables: need %llx, have %x\n",
			table_end - table_addr, TABLE_SIZE);
		return log_msg_ret("acpi", -ENOSPC);
	}
	gd->arch.table_end_high = table_end;

	log_debug("- done writing tables\n");

	return 0;
}

EVENT_SPY_SIMPLE(EVT_LAST_STAGE_INIT, alloc_write_acpi_tables);
