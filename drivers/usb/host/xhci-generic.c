// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 9elements GmbH
 *
 * GENERIC USB HOST xHCI Controller
 */

#include <asm/io.h>
#include <dm.h>
#include <fdtdec.h>
#include <log.h>
#include <usb.h>

#include <usb/xhci.h>

struct generic_xhci_plat {
	fdt_addr_t hcd_base;
};

/**
 * Contains pointers to register base addresses
 * for the usb controller.
 */
struct generic_xhci {
	struct xhci_ctrl ctrl;	/* Needs to come first in this struct! */
	struct usb_plat usb_plat;
	struct xhci_hccr *hcd;
};

/*
 * Dummy implementation that can be overwritten by a board
 * specific function
 */
__weak int board_xhci_enable(fdt_addr_t base)
{
	return 0;
}

static int xhci_usb_probe(struct udevice *dev)
{
	struct generic_xhci_plat *plat = dev_get_plat(dev);
	struct generic_xhci *ctx = dev_get_priv(dev);
	struct xhci_hcor *hcor;
	int len;

	ctx->hcd = (struct xhci_hccr *)phys_to_virt(plat->hcd_base);
	len = HC_LENGTH(xhci_readl(&ctx->hcd->cr_capbase));
	hcor = (struct xhci_hcor *)((uintptr_t)ctx->hcd + len);

	/* Enable USB xHCI in board specific code */
	board_xhci_enable(devfdt_get_addr_index(dev, 1));

	return xhci_register(dev, ctx->hcd, hcor);
}

static int xhci_usb_of_to_plat(struct udevice *dev)
{
	struct generic_xhci_plat *plat = dev_get_plat(dev);

	/*
	 * Get the base address for XHCI controller from the device node
	 */
	plat->hcd_base = dev_read_addr(dev);
	if (plat->hcd_base == FDT_ADDR_T_NONE) {
		debug("Can't get the XHCI register base address\n");
		return -ENXIO;
	}

	return 0;
}

static const struct udevice_id xhci_usb_ids[] = {
	{ .compatible = "generic-xhci" },
	{ }
};

U_BOOT_DRIVER(usb_xhci) = {
	.name	= "xhci_generic",
	.id	= UCLASS_USB,
	.of_match = xhci_usb_ids,
	.of_to_plat = xhci_usb_of_to_plat,
	.probe = xhci_usb_probe,
	.remove = xhci_deregister,
	.ops	= &xhci_usb_ops,
	.plat_auto	= sizeof(struct generic_xhci_plat),
	.priv_auto	= sizeof(struct generic_xhci),
	.flags	= DM_FLAG_ALLOC_PRIV_DMA,
};
