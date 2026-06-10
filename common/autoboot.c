// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2000
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 */

#include <config.h>
#include <autoboot.h>
#include <bootretry.h>
#include <cli.h>
#include <command.h>
#include <console.h>
#include <env.h>
#include <errno.h>
#include <fdtdec.h>
#include <hash.h>
#include <log.h>
#include <malloc.h>
#include <memalign.h>
#include <menu.h>
#include <post.h>
#include <time.h>
#include <asm/global_data.h>
#include <linux/delay.h>
#include <u-boot/sha256.h>
#include <bootcount.h>
#include <crypt.h>
#include <dm/ofnode.h>
#ifdef is_boot_from_usb
#include <env.h>
#endif

DECLARE_GLOBAL_DATA_PTR;

#define DELAY_STOP_STR_MAX_LENGTH 64

#ifndef DEBUG_BOOTKEYS
#define DEBUG_BOOTKEYS 0
#endif
#define debug_bootkeys(fmt, args...)		\
	debug_cond(DEBUG_BOOTKEYS, fmt, ##args)

/* Stored value of bootdelay, used by autoboot_command() */
static int stored_bootdelay;
static int menukey;

static int advupdate(const char *ifname, const char *dev_part, const char *s)
{
	int ret = 0;
	char buf[256] = {0};
	bool haveconfig = true;

	//start usb device
	if (!strcmp(ifname,"usb"))
	{
		run_command("usb start", 0);
	}

	else if (!strcmp(ifname, "mmc"))
	{
		//load config file
		env_set_ulong("filesize",0);
		sprintf(buf, "fatload %s %s ${loadaddr} ${advufile};env import -t ${loadaddr} ${filesize}", ifname, dev_part);
		run_command_list(buf, -1, 0);
		if (env_get_ulong("filesize", 16, 0) == 0) {
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "ext2load %s %s ${loadaddr} ${advufile};env import -t ${loadaddr} ${filesize}", ifname, dev_part);
			run_command_list(buf, -1, 0);
			if (env_get_ulong("filesize", 16, 0) == 0) {
				// config file not found!
				//printf("%s %s config file not found!\n", ifname, dev_part);
				haveconfig = false;
			}
		}

		// find update.bin file
		if (!haveconfig)
		{
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "if test -e %s %s update.bin; then setenv advupdatebin y; fi", ifname, dev_part);
			run_command_list(buf, -1, 0);
			if (env_get_yesno("advupdatebin") != 1)
			{
				// update.bin file not found!
				//printf("%s %s update bin file not found!\n", ifname, dev_part);
				return 0;
			}
		}
	}
	else if (!strcmp(ifname, "nand"))
	{
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "ubi part NAND.recovery && ubifsmount ubi0;ubifsload ${loadaddr} ${advufile};env import -t ${loadaddr} ${filesize}");
	run_command_list(buf, -1, 0);
		run_command_list("ubifsumount", -1, 0);
		if (env_get_ulong("filesize", 16, 0) == 0) {
			// config file not found!
			//printf("nand config file not found!!\n");
			haveconfig = false;
		}

		// find update.bin file
		if (!haveconfig)
		{
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "ubi part NAND.recovery && ubifsmount ubi0;ubifsload ${loadaddr} update.bin 0x10;env import -t ${loadaddr} 0x10");
			run_command_list(buf, -1, 0);
			run_command_list("ubifsumount", -1, 0);
			if (env_get_ulong("filesize", 16, 0) == 0)
			{
				// update.bin file not found!
				//printf("nand update bin file not found!!\n");
				return 0;
			}
			else
			{
				run_command("setenv advupdatebin y", 0);
			}
		}
	}

	if (haveconfig)
		printf("Config file found!\n");
	else if (env_get_yesno("advupdatebin") == 1)
		printf("update bin file found!\n");
	else
		return 0;

	if ((env_get_ulong("filesize",16,0) > 0) || (env_get_yesno("advupdatebin") == 1))
	{
#if 1 //+= ramdisk boot
		if ((env_get_yesno("advimage") == 1) || (env_get_yesno("advrootfs") == 1) || (env_get_yesno("advrecover") == 1) || (env_get_yesno("advupdatebin") == 1))
		{
			ret = 2;
			printf("System recovery mode!\n");
			if (!strcmp(ifname, "mmc"))
			{
				if (env_get_yesno("advupdatebin") == 1)
				{
					run_command("setenv mmcdev 0", 0);
				}
				else
				{
					if (!strcmp(dev_part, "1:1"))
					{
						run_command("setenv mmcdev 1", 0);
					}
					else if (!strcmp(dev_part, "0:3"))
					{
						run_command("setenv mmcdev 0", 0);
					}
				}
				run_command("mmc dev ${mmcdev}", 0);

				s = env_get("advrfs");
				run_command_list(s, -1, 0);
			}
			else if (!strcmp(ifname, "usb"))
			{
				s = env_get("advrfs");
				run_command_list(s, -1, 0);
			}
		}
		else
		{
			printf("System boot mode!\n");
			s = env_get("bootcmd");
		}
#endif
	}
	else
		printf("Normal boot mode!\n");

	return ret;
}

#if defined(CONFIG_AUTOBOOT_STOP_STR_CRYPT)
#define AUTOBOOT_STOP_STR_CRYPT	CONFIG_AUTOBOOT_STOP_STR_CRYPT
#else
#define AUTOBOOT_STOP_STR_CRYPT	""
#endif
#if defined(CONFIG_AUTOBOOT_STOP_STR_SHA256)
#define AUTOBOOT_STOP_STR_SHA256	CONFIG_AUTOBOOT_STOP_STR_SHA256
#else
#define AUTOBOOT_STOP_STR_SHA256	""
#endif

#ifdef CONFIG_AUTOBOOT_USE_MENUKEY
#define AUTOBOOT_MENUKEY CONFIG_AUTOBOOT_MENUKEY
#else
#define AUTOBOOT_MENUKEY 0
#endif

/**
 * passwd_abort_crypt() - check for a crypt-style hashed key sequence to abort booting
 *
 * This checks for the user entering a password within a given time.
 *
 * The entered password is hashed via one of the crypt-style hash methods
 * and compared to the pre-defined value from either
 *   the environment variable "bootstopkeycrypt"
 * or
 *   the config value CONFIG_AUTOBOOT_STOP_STR_CRYPT
 *
 * In case the config value CONFIG_AUTOBOOT_NEVER_TIMEOUT has been enabled
 * this function never times out if the user presses the <Enter> key
 * before starting to enter the password.
 *
 * @etime: Timeout value ticks (stop when get_ticks() reachs this)
 * Return: 0 if autoboot should continue, 1 if it should stop
 */
static int passwd_abort_crypt(uint64_t etime)
{
	const char *crypt_env_str = env_get("bootstopkeycrypt");
	char presskey[DELAY_STOP_STR_MAX_LENGTH];
	u_int presskey_len = 0;
	int abort = 0;
	int never_timeout = 0;
	int err;

	if (IS_ENABLED(CONFIG_AUTOBOOT_STOP_STR_ENABLE) && !crypt_env_str)
		crypt_env_str = AUTOBOOT_STOP_STR_CRYPT;

	if (!crypt_env_str)
		return 0;

	/* We expect the stop-string to be newline-terminated */
	do {
		if (tstc()) {
			/* Check for input string overflow */
			if (presskey_len >= sizeof(presskey))
				return 0;

			presskey[presskey_len] = getchar();

			if ((presskey[presskey_len] == '\r') ||
			    (presskey[presskey_len] == '\n')) {
				if (IS_ENABLED(CONFIG_AUTOBOOT_NEVER_TIMEOUT) &&
				    !presskey_len) {
					never_timeout = 1;
					continue;
				}
				presskey[presskey_len] = '\0';
				err = crypt_compare(crypt_env_str, presskey,
						    &abort);
				if (err)
					debug_bootkeys(
						"crypt_compare() failed with: %s\n",
						errno_str(err));
				/* you had one chance */
				break;
			} else {
				presskey_len++;
			}
		}
		udelay(10000);
	} while (never_timeout || get_ticks() <= etime);

	return abort;
}

/*
 * Use a "constant-length" time compare function for this
 * hash compare:
 *
 * https://crackstation.net/hashing-security.htm
 */
static int slow_equals(u8 *a, u8 *b, int len)
{
	int diff = 0;
	int i;

	for (i = 0; i < len; i++)
		diff |= a[i] ^ b[i];

	return diff == 0;
}

/**
 * passwd_abort_sha256() - check for a hashed key sequence to abort booting
 *
 * This checks for the user entering a SHA256 hash within a given time.
 *
 * @etime: Timeout value ticks (stop when get_ticks() reachs this)
 * Return: 0 if autoboot should continue, 1 if it should stop
 */
static int passwd_abort_sha256(uint64_t etime)
{
	const char *sha_env_str = env_get("bootstopkeysha256");
	u8 sha_env[SHA256_SUM_LEN];
	u8 *sha;
	char *presskey;
	char *c;
	const char *algo_name = "sha256";
	u_int presskey_len = 0;
	int abort = 0;
	int size = sizeof(sha);
	int ret;

	if (sha_env_str == NULL)
		sha_env_str = AUTOBOOT_STOP_STR_SHA256;

	presskey = malloc_cache_aligned(DELAY_STOP_STR_MAX_LENGTH);
	if (!presskey)
		return -ENOMEM;

	c = strstr(sha_env_str, ":");
	if (c && (c - sha_env_str < DELAY_STOP_STR_MAX_LENGTH)) {
		/* preload presskey with salt */
		memcpy(presskey, sha_env_str, c - sha_env_str);
		presskey_len = c - sha_env_str;
		sha_env_str = c + 1;
	}
	/*
	 * Generate the binary value from the environment hash value
	 * so that we can compare this value with the computed hash
	 * from the user input
	 */
	ret = hash_parse_string(algo_name, sha_env_str, sha_env);
	if (ret) {
		printf("Hash %s not supported!\n", algo_name);
		return 0;
	}

	sha = malloc_cache_aligned(SHA256_SUM_LEN);
	size = SHA256_SUM_LEN;
	/*
	 * We don't know how long the stop-string is, so we need to
	 * generate the sha256 hash upon each input character and
	 * compare the value with the one saved in the environment
	 */
	do {
		if (tstc()) {
			/* Check for input string overflow */
			if (presskey_len >= DELAY_STOP_STR_MAX_LENGTH) {
				free(presskey);
				free(sha);
				return 0;
			}

			presskey[presskey_len++] = getchar();

			/* Calculate sha256 upon each new char */
			hash_block(algo_name, (const void *)presskey,
				   presskey_len, sha, &size);

			/* And check if sha matches saved value in env */
			if (slow_equals(sha, sha_env, SHA256_SUM_LEN))
				abort = 1;
		}
		udelay(10000);
	} while (!abort && get_ticks() <= etime);

	free(presskey);
	free(sha);
	return abort;
}

/**
 * passwd_abort_key() - check for a key sequence to aborted booting
 *
 * This checks for the user entering a string within a given time.
 *
 * @etime: Timeout value ticks (stop when get_ticks() reachs this)
 * Return: 0 if autoboot should continue, 1 if it should stop
 */
static int passwd_abort_key(uint64_t etime)
{
	int abort = 0;
	struct {
		char *str;
		u_int len;
		int retry;
	}
	delaykey[] = {
		{ .str = env_get("bootdelaykey"),  .retry = 1 },
		{ .str = env_get("bootstopkey"),   .retry = 0 },
	};

	char presskey[DELAY_STOP_STR_MAX_LENGTH];
	int presskey_len = 0;
	int presskey_max = 0;
	int i;

#  ifdef CONFIG_AUTOBOOT_DELAY_STR
	if (delaykey[0].str == NULL)
		delaykey[0].str = CONFIG_AUTOBOOT_DELAY_STR;
#  endif
#  ifdef CONFIG_AUTOBOOT_STOP_STR
	if (delaykey[1].str == NULL)
		delaykey[1].str = CONFIG_AUTOBOOT_STOP_STR;
#  endif

	for (i = 0; i < sizeof(delaykey) / sizeof(delaykey[0]); i++) {
		delaykey[i].len = delaykey[i].str == NULL ?
				    0 : strlen(delaykey[i].str);
		delaykey[i].len = delaykey[i].len > DELAY_STOP_STR_MAX_LENGTH ?
				    DELAY_STOP_STR_MAX_LENGTH : delaykey[i].len;

		presskey_max = presskey_max > delaykey[i].len ?
				    presskey_max : delaykey[i].len;

		debug_bootkeys("%s key:<%s>\n",
			       delaykey[i].retry ? "delay" : "stop",
			       delaykey[i].str ? delaykey[i].str : "NULL");
	}

	/* In order to keep up with incoming data, check timeout only
	 * when catch up.
	 */
	do {
		if (tstc()) {
			if (presskey_len < presskey_max) {
				presskey[presskey_len++] = getchar();
			} else {
				for (i = 0; i < presskey_max - 1; i++)
					presskey[i] = presskey[i + 1];

				presskey[i] = getchar();
			}
		}

		for (i = 0; i < sizeof(delaykey) / sizeof(delaykey[0]); i++) {
			if (delaykey[i].len > 0 &&
			    presskey_len >= delaykey[i].len &&
				memcmp(presskey + presskey_len -
					delaykey[i].len, delaykey[i].str,
					delaykey[i].len) == 0) {
					debug_bootkeys("got %skey\n",
						delaykey[i].retry ? "delay" :
						"stop");

				/* don't retry auto boot */
				if (!delaykey[i].retry)
					bootretry_dont_retry();
				abort = 1;
			}
		}
		udelay(10000);
	} while (!abort && get_ticks() <= etime);

	return abort;
}

/**
 * flush_stdin() - drops all pending characters from stdin
 */
static void flush_stdin(void)
{
	while (tstc())
		(void)getchar();
}

/**
 * fallback_to_sha256() - check whether we should fall back to sha256
 *                        password checking
 *
 * This checks for the environment variable `bootstopusesha256` in case
 * sha256-fallback has been enabled via the config setting
 * `AUTOBOOT_SHA256_FALLBACK`.
 *
 * Return: `false` if we must not fall-back, `true` if plain sha256 should be tried
 */
static bool fallback_to_sha256(void)
{
	if (IS_ENABLED(CONFIG_AUTOBOOT_SHA256_FALLBACK))
		return env_get_yesno("bootstopusesha256") == 1;
	else if (IS_ENABLED(CONFIG_CRYPT_PW))
		return false;
	else
		return true;
}

/***************************************************************************
 * Watch for 'delay' seconds for autoboot stop or autoboot delay string.
 * returns: 0 -  no key string, allow autoboot 1 - got key string, abort
 */
static int abortboot_key_sequence(int bootdelay)
{
	int abort;
	uint64_t etime = endtick(bootdelay);

	if (IS_ENABLED(CONFIG_AUTOBOOT_FLUSH_STDIN))
		flush_stdin();
#  ifdef CONFIG_AUTOBOOT_PROMPT
	/*
	 * CONFIG_AUTOBOOT_PROMPT includes the %d for all boards.
	 * To print the bootdelay value upon bootup.
	 */
	printf(CONFIG_AUTOBOOT_PROMPT, bootdelay);
#  endif

	if (IS_ENABLED(CONFIG_AUTOBOOT_ENCRYPTION)) {
		if (IS_ENABLED(CONFIG_CRYPT_PW) && !fallback_to_sha256())
			abort = passwd_abort_crypt(etime);
		else
			abort = passwd_abort_sha256(etime);
	} else {
		abort = passwd_abort_key(etime);
	}
	if (!abort)
		debug_bootkeys("key timeout\n");

	return abort;
}

static int abortboot_single_key(int bootdelay)
{
	int abort = 0;
	unsigned long ts;

	printf("Hit any key to stop autoboot: %2d ", bootdelay);

	/*
	 * Check if key already pressed
	 */
	if (tstc()) {	/* we got a key press	*/
		if (getchar() == 0x0d) // got enter key
		{
		puts("\b\b\b 0");
		abort = 1;	/* don't auto boot	*/
		}
	}

	while ((bootdelay > 0) && (!abort)) {
		--bootdelay;
		/* delay 1000 ms */
		ts = get_timer(0);
		do {
			if (tstc()) {	/* we got a key press	*/
				if (getchar() == 0x0d) // got enter key
				{
				int key;

				abort  = 1;	/* don't auto boot	*/
				bootdelay = 0;	/* no more delay	*/
				key = getchar();/* consume input	*/
				if (IS_ENABLED(CONFIG_AUTOBOOT_USE_MENUKEY))
					menukey = key;
				break;
				}
			}
			udelay(10000);
		} while (!abort && get_timer(ts) < 1000);

		printf("\b\b\b%2d ", bootdelay);
	}

	putc('\n');

	return abort;
}

static int abortboot(int bootdelay)
{
	int abort = 0;

	if (bootdelay >= 0) {
		if (autoboot_keyed())
			abort = abortboot_key_sequence(bootdelay);
		else
			abort = abortboot_single_key(bootdelay);
	}

	if (IS_ENABLED(CONFIG_SILENT_CONSOLE) && abort)
		gd->flags &= ~GD_FLG_SILENT;

	return abort;
}

static void process_fdt_options(void)
{
#ifdef CONFIG_TEXT_BASE
	ulong addr;

	/* Add an env variable to point to a kernel payload, if available */
	addr = ofnode_conf_read_int("kernel-offset", 0);
	if (addr)
		env_set_addr("kernaddr", (void *)(CONFIG_TEXT_BASE + addr));

	/* Add an env variable to point to a root disk, if available */
	addr = ofnode_conf_read_int("rootdisk-offset", 0);
	if (addr)
		env_set_addr("rootaddr", (void *)(CONFIG_TEXT_BASE + addr));
#endif /* CONFIG_TEXT_BASE */
}

const char *bootdelay_process(void)
{
	char *s;
	int bootdelay;

	bootcount_inc();

	s = env_get("bootdelay");
	bootdelay = s ? (int)simple_strtol(s, NULL, 10) : CONFIG_BOOTDELAY;

	/*
	 * Does it really make sense that the devicetree overrides the user
	 * setting? It is possibly helpful for security since the device tree
	 * may be signed whereas the environment is often loaded from storage.
	 */
	if (IS_ENABLED(CONFIG_OF_CONTROL))
		bootdelay = ofnode_conf_read_int("bootdelay", bootdelay);

#if defined(is_boot_from_usb)
	if (is_boot_from_usb() && env_get("bootcmd_mfg")) {
		disconnect_from_pc();
		printf("Boot from USB for mfgtools\n");
		bootdelay = 0;
		env_set_default("Use default environment for \
				 mfgtools\n", 0);
	} else if (is_boot_from_usb()) {
		printf("Boot from USB for uuu\n");
		env_set("bootcmd", "fastboot 0");
	} else {
		printf("Normal Boot\n");
	}
#endif

	debug("### main_loop entered: bootdelay=%d\n\n", bootdelay);

	if (IS_ENABLED(CONFIG_AUTOBOOT_MENU_SHOW))
		bootdelay = menu_show(bootdelay);
	bootretry_init_cmd_timeout();

#ifdef CONFIG_POST
	if (gd->flags & GD_FLG_POSTFAIL) {
		s = env_get("failbootcmd");
	} else
#endif /* CONFIG_POST */
	if (bootcount_error())
		s = env_get("altbootcmd");
	else
		s = env_get("bootcmd");

#if defined(is_boot_from_usb)
	if (is_boot_from_usb() && env_get("bootcmd_mfg")) {
		s = env_get("bootcmd_mfg");
		printf("Run bootcmd_mfg: %s\n", s);
	}
#endif

	if (IS_ENABLED(CONFIG_OF_CONTROL))
		process_fdt_options();
	stored_bootdelay = bootdelay;

	return s;
}

void autoboot_command(const char *s)
{
	debug("### main_loop: bootcmd=\"%s\"\n", s ? s : "<UNDEFINED>");

	if (s && (stored_bootdelay == -2 ||
		 (stored_bootdelay != -1 && !abortboot(stored_bootdelay)))) {
		bool lock;
		int prev;

		lock = autoboot_keyed() &&
			!IS_ENABLED(CONFIG_AUTOBOOT_KEYED_CTRLC);
		if (lock)
			prev = disable_ctrlc(1); /* disable Ctrl-C checking */

		{
			int ret = 0;
			ret = advupdate("mmc", "1:1", s);
			if (!ret)
				ret = advupdate("mmc", "0:3", s);
		}

		run_command_list(s, -1, 0);

		if (lock)
			disable_ctrlc(prev);	/* restore Ctrl-C checking */
	}

	if (IS_ENABLED(CONFIG_AUTOBOOT_USE_MENUKEY) &&
	    menukey == AUTOBOOT_MENUKEY) {
		s = env_get("menucmd");
		if (s)
			run_command_list(s, -1, 0);
	}
}
