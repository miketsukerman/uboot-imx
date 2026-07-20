// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2018-2021 NXP
 */

#define LOG_CATEGORY LOGC_ARCH
#include <stdlib.h>
#include <errno.h>
#include <imx_container.h>
#include <log.h>
#include <mapmem.h>
#include <spl.h>
#include <cpu_func.h>
#include <asm/unaligned.h>
#ifdef CONFIG_AHAB_BOOT
#include <asm/mach-imx/ahab.h>
#endif
#if IS_ENABLED(CONFIG_IMX_CRRM)
#define IMG_TYPE_RECOVERY		0x09
#endif
#include <u-boot/lz4.h>
#ifdef CONFIG_IMX_TRUSTY_OS
#define TEE_DEST_SIZE   0x04000000
#define LZ4_MAGIC_NUM	0x184D2204
#define LZ4_OFFSET	0x00800000
#endif

/*
 * Verbose SPL container load logging to help narrow down image load / entry
 * point problems (e.g. jumping into an unloaded / all-zero image). Emitted via
 * printf() so it is visible without a full DEBUG build. Set to 0 to silence.
 */
#define IMX_CTNR_LOG_ENABLED	1
#define ctnr_log(fmt, args...)						\
	do {								\
		if (IMX_CTNR_LOG_ENABLED)				\
			printf("[IMX-CTNR] " fmt, ##args);		\
	} while (0)

__weak bool arch_check_dst_in_secure(void *start, ulong size)
{
	return false;
}

__weak void *arch_get_container_trampoline(void)
{
	return NULL;
}

void __weak arch_spl_load_configure(struct spl_image_info *spl_image)
{
	return;
}

static struct boot_img_t *read_auth_image(struct spl_image_info *spl_image,
					  struct spl_load_info *info,
					  struct container_hdr *container,
					  int image_index,
					  ulong container_offset)
{
	struct boot_img_t *images;
	ulong offset, size;
	ulong read;
	void *buf, *trampoline;

	if (image_index > container->num_images) {
		debug("Invalid image number\n");
		return NULL;
	}

	images = (struct boot_img_t *)((u8 *)container +
				       sizeof(struct container_hdr));

	if (!IS_ALIGNED(images[image_index].offset, spl_get_bl_len(info))) {
		printf("%s: image%d offset not aligned to %u\n",
		       __func__, image_index, spl_get_bl_len(info));
		return NULL;
	}

#if IS_ENABLED(CONFIG_IMX_CRRM)
	if ((images[image_index].hab_flags & 0xF) == IMG_TYPE_RECOVERY) {
		if (!spl_image->recovery) {
			debug("Skip recovery image %d\n", image_index);
			return &images[image_index];
		}
	}
#endif

	size = ALIGN(images[image_index].size, spl_get_bl_len(info));
	offset = images[image_index].offset + container_offset;

	ctnr_log("read_auth_image[%d]: file_off 0x%lx dst 0x%llx entry 0x%llx size 0x%lx(aligned) raw_size 0x%x flags 0x%x\n",
		 image_index, offset,
		 (unsigned long long)images[image_index].dst,
		 (unsigned long long)images[image_index].entry,
		 size, images[image_index].size, images[image_index].hab_flags);

	debug("%s: container: %p offset: %lu size: %lu\n", __func__,
	      container, offset, size);

	buf = map_sysmem(images[image_index].dst, images[image_index].size);
	if (IS_ENABLED(CONFIG_SPL_IMX_CONTAINER_USE_TRAMPOLINE) &&
	    arch_check_dst_in_secure(buf, size)) {
		trampoline = arch_get_container_trampoline();
		if (!trampoline) {
			printf("%s: trampoline size is zero\n", __func__);
			return NULL;
		}

		ctnr_log("read_auth_image[%d]: loading via trampoline %p to secure dst %p\n",
			 image_index, trampoline, buf);

		read = info->read(info, offset, size, trampoline);
		ctnr_log("read_auth_image[%d]: trampoline read returned 0x%lx (expected >= 0x%x)\n",
			 image_index, read, images[image_index].size);
		if (read < images[image_index].size) {
			printf("%s: failed to load image to a trampoline buffer\n", __func__);
			return NULL;
		}

		memcpy(buf, trampoline, images[image_index].size);
	} else {
		read = info->read(info, offset, size, buf);
		ctnr_log("read_auth_image[%d]: read returned 0x%lx (expected >= 0x%x) into dst %p\n",
			 image_index, read, images[image_index].size, buf);
		if (read < images[image_index].size) {
			printf("%s: failed to load image to a non-secure region\n", __func__);
			return NULL;
		}
	}

	if (IMX_CTNR_LOG_ENABLED) {
		u32 w[4];
		int j;

		for (j = 0; j < 4; j++)
			w[j] = get_unaligned((u32 *)buf + j);

		ctnr_log("read_auth_image[%d]: first words @dst 0x%llx: %08x %08x %08x %08x\n",
			 image_index, (unsigned long long)images[image_index].dst,
			 w[0], w[1], w[2], w[3]);
		if (!w[0] && !w[1] && !w[2] && !w[3])
			ctnr_log("read_auth_image[%d]: WARNING destination looks empty (all zero) after load\n",
				 image_index);
	}

#ifdef CONFIG_AHAB_BOOT
	flush_dcache_range((ulong)buf, (ulong)(buf + images[image_index].size - 1));
	if (ahab_verify_cntr_image(&images[image_index], image_index))
		return NULL;
#endif

#ifdef CONFIG_IMX_TRUSTY_OS
	size_t dest_size = TEE_DEST_SIZE;

	if (IS_ENABLED(CONFIG_SPL_LZ4)) {
                u32 *lz4_magic_num = (void *)images[image_index].entry;

                if (*lz4_magic_num == LZ4_MAGIC_NUM)
		{
			memcpy((void *)(images[image_index].entry + LZ4_OFFSET),
					(void *)images[image_index].entry, images[image_index].size);
			if (ulz4fn((void *)(images[image_index].entry+ LZ4_OFFSET), images[image_index].size,
					(void *)images[image_index].entry, &dest_size))
			{
				printf("Decompress image fail!\n");
				return NULL;
			}
			images[image_index].size = dest_size;
		}
	}
#endif

	return &images[image_index];
}

static int read_auth_container(struct spl_image_info *spl_image,
			       struct spl_load_info *info, ulong offset)
{
	struct container_hdr *container = NULL;
	struct container_hdr *authhdr;
	u16 length;
	int i, size, ret = 0;

	size = ALIGN(CONTAINER_HDR_ALIGNMENT, spl_get_bl_len(info));

	/*
	 * It will not override the ATF code, so safe to use it here,
	 * no need malloc
	 */
	container = malloc(size);
	if (!container)
		return -ENOMEM;

	debug("%s: container: %p offset: %lu size: %u\n", __func__,
	      container, offset, size);
	ctnr_log("read_auth_container: reading hdr @off 0x%lx size 0x%x bl_len %u\n",
		 offset, size, spl_get_bl_len(info));
	if (info->read(info, offset, size, container) <
	    CONTAINER_HDR_ALIGNMENT) {
		ctnr_log("read_auth_container: short read of container header @0x%lx\n",
			 offset);
		ret = -EIO;
		goto end;
	}

	ctnr_log("read_auth_container: hdr tag 0x%02x ver 0x%02x num_images %u sig_blk_off 0x%x\n",
		 container->tag, container->version, container->num_images,
		 container->sig_blk_offset);

	if (!valid_container_hdr(container)) {
		log_err("Wrong container header\n");
		ret = -ENOENT;
		goto end;
	}

	if (!container->num_images) {
		log_err("Wrong container, no image found\n");
		ret = -ENOENT;
		goto end;
	}

	length = container->length_lsb + (container->length_msb << 8);
	debug("Container length %u\n", length);

	if (length > CONTAINER_HDR_ALIGNMENT) {
		size = ALIGN(length, spl_get_bl_len(info));

		free(container);
		container = malloc(size);
		if (!container)
			return -ENOMEM;

		debug("%s: container: %p offset: %lu size: %u\n",
		      __func__, container, offset, size);
		if (info->read(info, offset, size, container) < length) {
			ret = -EIO;
			goto end;
		}
	}

	authhdr = container;

#ifdef CONFIG_AHAB_BOOT
	authhdr = ahab_auth_cntr_hdr(authhdr, length);
	if (!authhdr) {
		ret = -EINVAL;
		goto end_auth;
	}
#endif

	for (i = 0; i < authhdr->num_images; i++) {
		struct boot_img_t *image = read_auth_image(spl_image, info,
							   authhdr, i,
							   offset);

		if (!image) {
			ret = -EINVAL;
			goto end_auth;
		}

		if (i == 0) {
			spl_image->load_addr = image->dst;
			spl_image->entry_point = image->entry;
			ctnr_log("read_auth_container: image 0 -> load_addr 0x%lx entry_point 0x%lx\n",
				 spl_image->load_addr, spl_image->entry_point);
		}
	}

	ctnr_log("read_auth_container: done, SPL will hand off load_addr 0x%lx entry_point 0x%lx\n",
		 spl_image->load_addr, spl_image->entry_point);

#if defined(CONFIG_SPL_BUILD) && defined(CONFIG_IMX_TRUSTY_OS)
	/* Everything checks out, get the sw_version now. */
	spl_image->rbindex = (uint64_t)container->sw_version;
#endif


end_auth:
#ifdef CONFIG_AHAB_BOOT
	ahab_auth_release();
#endif

end:
	free(container);

	return ret;
}

int spl_load_imx_container(struct spl_image_info *spl_image,
			   struct spl_load_info *info, ulong offset)
{
	arch_spl_load_configure(spl_image);
	return read_auth_container(spl_image, info, offset);
}
