/*
 * File: ldr.h
 *
 * Copyright 2009-2010 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * View LDR contents; based on the "Visual DSP++ 4.0 Loader Manual"
 * and misc Blackfin HRMs
 */

#ifndef __SDP_H__
#define __SDP_H__

#define ADI_SDP_USB_VID                0x0456
#define ADI_SDP_USB_PID                0xb630

#define ADI_SDP_WRITE_ENDPOINT         0x06
#define ADI_SDP_READ_ENDPOINT          0x05

#define ADI_SDP_CMD_GROUP_BASE         0xCA000000
#define ADI_SDP_CMD_FLASH_LED          (ADI_SDP_CMD_GROUP_BASE | 0x01)
#define ADI_SDP_CMD_GET_FW_VERSION     (ADI_SDP_CMD_GROUP_BASE | 0x02)
#define ADI_SDP_CMD_SDRAM_PROGRAM_BOOT (ADI_SDP_CMD_GROUP_BASE | 0x03)
#define ADI_SDP_CMD_READ_ID_EEPROMS    (ADI_SDP_CMD_GROUP_BASE | 0x04)
#define ADI_SDP_CMD_RESET_BOARD        (ADI_SDP_CMD_GROUP_BASE | 0x05)
#define ADI_SDP_CMD_READ_MAC_ADDRESS   (ADI_SDP_CMD_GROUP_BASE | 0x06)
#define ADI_SDP_CMD_STOP_STREAM        (ADI_SDP_CMD_GROUP_BASE | 0x07)

#define ADI_SDP_CMD_GROUP_USER         0xF8000000
#define ADI_SDP_CMD_USER_GET_GUID      (ADI_SDP_CMD_GROUP_USER | 0x01)
#define ADI_SDP_CMD_USER_MAX           (ADI_SDP_CMD_GROUP_USER | 0xFF)

#endif
