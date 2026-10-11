// SPDX-License-Identifier: GPL-2.0
/*
 * A TPM 2.0 chip backed by the TPM on the Raspberry Pi 4's VPU.
 *
 * pi4-server-firmware's start4.elf answers TPM 2.0 commands over the
 * property mailbox (tag 0x000300a3): the command goes in the tag's value, and
 * the response comes back in the same place. Its device tree handed over a
 * "vpu-tpm" node for this driver to bind to, so a kernel with the module
 * installed finds it without being told.
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/tpm.h>
#include <linux/version.h>
#include <soc/bcm2835/raspberrypi-firmware.h>

/* Exported by the TPM core, and declared in drivers/char/tpm/tpm.h. */
struct tpm_chip *tpmm_chip_alloc(struct device *pdev, const struct tpm_class_ops *ops);
int tpm_chip_register(struct tpm_chip *chip);
void tpm_chip_unregister(struct tpm_chip *chip);

#define RPI_FIRMWARE_TPM2_COMMAND	0x000300a3
#define TPM_MAX				2048
#define TPM_HEADER			10

struct vpu_tpm {
	struct rpi_firmware *fw;
	u8 response[TPM_MAX];
	size_t response_len;
	bool ready;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
static int vpu_tpm_send(struct tpm_chip *chip, u8 *buf, size_t bufsiz, size_t cmd_len)
#else
static int vpu_tpm_send(struct tpm_chip *chip, u8 *buf, size_t cmd_len)
#endif
{
	struct vpu_tpm *vt = dev_get_drvdata(&chip->dev);
	u8 *message;
	size_t len;
	int ret;

	if (cmd_len < TPM_HEADER || cmd_len > TPM_MAX)
		return -EINVAL;

	message = kzalloc(TPM_MAX, GFP_KERNEL);
	if (!message)
		return -ENOMEM;
	memcpy(message, buf, cmd_len);

	ret = rpi_firmware_property(vt->fw, RPI_FIRMWARE_TPM2_COMMAND, message, TPM_MAX);
	if (ret)
		goto out;

	len = get_unaligned_be32(message + 2);
	if (len < TPM_HEADER || len > TPM_MAX) {
		ret = -EIO;
		goto out;
	}
	memcpy(vt->response, message, len);
	vt->response_len = len;
	vt->ready = true;
out:
	kfree(message);
	return ret;
}

static int vpu_tpm_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{
	struct vpu_tpm *vt = dev_get_drvdata(&chip->dev);
	size_t len = min(count, vt->response_len);

	memcpy(buf, vt->response, len);
	vt->ready = false;
	return len;
}

static u8 vpu_tpm_status(struct tpm_chip *chip)
{
	struct vpu_tpm *vt = dev_get_drvdata(&chip->dev);

	return vt->ready ? 1 : 0;
}

static void vpu_tpm_cancel(struct tpm_chip *chip)
{
}

static bool vpu_tpm_req_canceled(struct tpm_chip *chip, u8 status)
{
	return false;
}

static const struct tpm_class_ops vpu_tpm_ops = {
	.flags = TPM_OPS_AUTO_STARTUP,
	.req_complete_mask = 1,
	.req_complete_val = 1,
	.req_canceled = vpu_tpm_req_canceled,
	.recv = vpu_tpm_recv,
	.send = vpu_tpm_send,
	.cancel = vpu_tpm_cancel,
	.status = vpu_tpm_status,
};

static int vpu_tpm_probe(struct platform_device *pdev)
{
	struct device_node *firmware;
	struct tpm_chip *chip;
	struct vpu_tpm *vt;
	static const u8 get_capability[] = {
		0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a,
		0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
	};
	u8 *probe;
	int ret;

	vt = devm_kzalloc(&pdev->dev, sizeof(*vt), GFP_KERNEL);
	if (!vt)
		return -ENOMEM;

	firmware = of_find_compatible_node(NULL, NULL, "raspberrypi,bcm2835-firmware");
	if (!firmware)
		return -ENODEV;
	vt->fw = devm_rpi_firmware_get(&pdev->dev, firmware);
	of_node_put(firmware);
	if (!vt->fw)
		return -EPROBE_DEFER;

	/* The node is there whatever the firmware: ask it for a property. */
	probe = kzalloc(TPM_MAX, GFP_KERNEL);
	if (!probe)
		return -ENOMEM;
	memcpy(probe, get_capability, sizeof(get_capability));
	ret = rpi_firmware_property(vt->fw, RPI_FIRMWARE_TPM2_COMMAND, probe, TPM_MAX);
	ret = ret ? ret : get_unaligned_be32(probe + 6);
	kfree(probe);
	if (ret) {
		dev_info(&pdev->dev, "the firmware has no TPM\n");
		return -ENODEV;
	}

	chip = tpmm_chip_alloc(&pdev->dev, &vpu_tpm_ops);
	if (IS_ERR(chip))
		return PTR_ERR(chip);
	chip->flags |= TPM_CHIP_FLAG_TPM2;
	dev_set_drvdata(&chip->dev, vt);
	platform_set_drvdata(pdev, chip);

	return tpm_chip_register(chip);
}

static void vpu_tpm_remove(struct platform_device *pdev)
{
	tpm_chip_unregister(platform_get_drvdata(pdev));
}

static const struct of_device_id vpu_tpm_of_match[] = {
	{ .compatible = "rusty-pi,pi4-vpu-tpm" },
	{ }
};
MODULE_DEVICE_TABLE(of, vpu_tpm_of_match);

static struct platform_driver vpu_tpm_driver = {
	.probe = vpu_tpm_probe,
	.remove = vpu_tpm_remove,
	.driver = {
		.name = "tpm_vpu",
		.of_match_table = vpu_tpm_of_match,
	},
};
module_platform_driver(vpu_tpm_driver);

MODULE_DESCRIPTION("TPM 2.0 on the Raspberry Pi 4's VPU, over the firmware mailbox");
MODULE_LICENSE("GPL");
