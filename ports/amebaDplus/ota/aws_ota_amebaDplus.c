/*
Amazon FreeRTOS OTA PAL for Realtek Ameba V1.0.0
Copyright (C) 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 http://aws.amazon.com/freertos
 http://www.FreeRTOS.org
*/

/* OTA PAL implementation for Realtek Ameba platform. */
#include "ota.h"
#include "ota_pal.h"
#include "ota_interface_private.h"
#include "ota_config.h"
#include "iot_crypto.h"
#include "core_pkcs11.h"
#include "amazon/example_amazon_freertos.h"
#include "flash_api.h"
#include "ameba_ota.h"
#include "platform_stdlib.h"

#define OTA_MEMDUMP 0
#define OTA_PRINT DiagPrintf

static uint32_t aws_ota_imgaddr = 0;
static uint32_t aws_ota_imgsz = 0;
static bool aws_ota_target_hdr_get = false;
static uint32_t ota_target_index = OTA_INDEX_2;
static uint32_t HdrIdx = 0;
static update_ota_target_hdr aws_ota_target_hdr;
update_manifest_info aws_manifest;
static bool aws_manifest_get = false;


#if 0 // move to example_amazon_freertos.h
#define AWS_OTA_IMAGE_STATE_FLASH_OFFSET             ( 0x1DB000 )
#endif
#define AWS_OTA_IMAGE_STATE_FLAG_IMG_NEW             0xffffffffU /* 11111111b A new image that hasn't yet been run. */
#define AWS_OTA_IMAGE_STATE_FLAG_PENDING_COMMIT      0xfffffffeU /* 11111110b Image is pending commit and is ready for self test. */
#define AWS_OTA_IMAGE_STATE_FLAG_IMG_VALID           0xfffffffcU /* 11111100b The image was accepted as valid by the self test code. */
#define AWS_OTA_IMAGE_STATE_FLAG_IMG_INVALID         0xfffffff8U /* 11111000b The image was NOT accepted by the self test code. */

typedef struct {
    int32_t lFileHandle;
} ameba_ota_context_t;

static ameba_ota_context_t ota_ctx;

#if OTA_MEMDUMP
void vMemDump(u32 addr, const u8 *start, u32 size, char * strHeader)
{
    int row, column, index, index2, max;
    u8 *buf, *line;

    if(!start ||(size==0))
            return;

    line = (u8*)start;

    /*
    16 bytes per line
    */
    if (strHeader)
       printf ("%s", strHeader);

    column = size % 16;
    row = (size / 16) + 1;
    for (index = 0; index < row; index++, line += 16)
    {
        buf = (u8*)line;

        max = (index == row - 1) ? column : 16;
        if ( max==0 ) break; /* If we need not dump this line, break it. */

        printf ("\n[%08x] ", addr + index*16 - (aws_ota_imgaddr - SPI_FLASH_BASE));

        //Hex
        for (index2 = 0; index2 < max; index2++)
        {
            if (index2 == 8)
            printf ("  ");
            printf ("%02x ", (u8) buf[index2]);
        }

        if (max != 16)
        {
            if (max < 8)
                printf ("  ");
            for (index2 = 16 - max; index2 > 0; index2--)
                printf ("   ");
        }

    }

    printf ("\n");
    return;
}
#endif

static int prvGet_ota_tartget_header(u8* buf, u32 len, update_ota_target_hdr * pOtaTgtHdr, u8 target_idx)
{
    update_file_img_hdr * ImgHdr;
    update_file_hdr * FileHdr;
    u8 * pTempAddr;
    u32 i = 0, j = 0;
    int index = -1;

    /*check if buf and len is valid or not*/
    if((len < (sizeof(update_file_img_hdr) + 8)) || (!buf)) {
        goto error;
    }

    FileHdr = (update_file_hdr *)buf;
    ImgHdr = (update_file_img_hdr *)(buf + 8);
    pTempAddr = buf + 8;

    if(len < (FileHdr->HdrNum * ImgHdr->ImgHdrLen + 8)) {
        goto error;
    }

    /*get the target OTA header from the new firmware file header*/
    for(i = 0; i < FileHdr->HdrNum; i++) {
        index = -1;
        pTempAddr = buf + 8 + ImgHdr->ImgHdrLen * i;

        if(strncmp("OTA", (const char *)pTempAddr, 3) == 0)
            index = 0;
        else
            goto error;

        if(index >= 0) {
            _memcpy((u8*)(&pOtaTgtHdr->FileImgHdr[j]), pTempAddr, sizeof(update_file_img_hdr));
            j++;
        }
    }

    pOtaTgtHdr->ValidImgCnt = j;

    if(j == 0) {
        printf("\n\r[%s] no valid image\n", __FUNCTION__);
        goto error;
    }

    return 1;
error:
    return 0;
}

static void prvSysReset_rtl8721d(u32 timeout_ms)
{
    vTaskDelay(timeout_ms);
    sys_reset();
}

OtaPalStatus_t prvPAL_Abort_rtl8721d(OtaFileContext_t *C)
{
    if (C != NULL && C->pFile != NULL) {
        LogInfo(("[%s] Abort OTA update", __FUNCTION__));
        C->pFile = NULL;
        ota_ctx.lFileHandle = 0x0;
    }
    return OTA_PAL_COMBINE_ERR(OtaPalSuccess, 0);
}

bool prvPAL_CreateFileForRx_rtl8721d(OtaFileContext_t *C)
{
    OtaPalMainStatus_t mainErr = OtaPalSuccess;
    OtaPalSubStatus_t subErr = 0;

    int block_cnt = 0;
    int i=0;
    flash_t flash;

    uint32_t ImgId = OTA_IMGID_APP;

    if (ota_get_cur_index(ImgId) == OTA_INDEX_1)
        ota_target_index = OTA_INDEX_2;
    else
        ota_target_index = OTA_INDEX_1;

	C->pFile = (uint8_t*)&ota_ctx;
    ota_ctx.lFileHandle = IMG_ADDR[ImgId][ota_target_index];// - SPI_FLASH_BASE;
    block_cnt = ((C->fileSize - 1) / (1024*64)) + 1;

    if (ota_ctx.lFileHandle > SPI_FLASH_BASE)
    {
        OTA_PRINT("[OTA] valid ota addr (0x%x) \r\n", ota_ctx.lFileHandle);
        aws_ota_imgaddr = ota_ctx.lFileHandle;
        aws_ota_imgsz = 0;
        aws_ota_target_hdr_get = false;
        memset((void *)&aws_ota_target_hdr, 0, sizeof(update_ota_target_hdr));
        memset((void *)&aws_manifest, 0, sizeof(update_manifest_info));

        for( i = 0; i < block_cnt; i++)
        {
            OTA_PRINT("[OTA] Erase block @ 0x%x\n", ota_ctx.lFileHandle - SPI_FLASH_BASE + i * (64 * 1024));
            flash_erase_block(&flash, aws_ota_imgaddr - SPI_FLASH_BASE + i * (64 * 1024));
        }
    }
    else {
        OTA_PRINT("[OTA] invalid ota addr (%d) \r\n", ota_ctx.lFileHandle);
        ota_ctx.lFileHandle = NULL;      /* Nullify the file handle in all error cases. */
    }

    if(ota_ctx.lFileHandle <= SPI_FLASH_BASE)
        mainErr = OtaPalRxFileCreateFailed;

    return OTA_PAL_COMBINE_ERR(mainErr, subErr);
}

/* Read the specified signer certificate from the filesystem into a local buffer. The
 * allocated memory becomes the property of the caller who is responsible for freeing it.
 */
uint8_t * prvPAL_ReadAndAssumeCertificate_rtl8721d(const uint8_t * const pucCertName, int32_t * const lSignerCertSize)
{
    uint8_t*    pucCertData;
    uint32_t    ulCertSize;
    uint8_t     *pucSignerCert = NULL;

    extern BaseType_t PKCS11_PAL_GetObjectValue( const char * pcFileName,
                               uint8_t ** ppucData,
                               uint32_t * pulDataSize );

    if ( PKCS11_PAL_GetObjectValue( (const char *) pucCertName, &pucCertData, &ulCertSize ) != pdTRUE )
    {   /* Use the back up "codesign_keys.h" file if the signing credentials haven't been saved in the device. */
        pucCertData = (uint8_t*) otapalconfigCODE_SIGNING_CERTIFICATE;
        ulCertSize = sizeof( otapalconfigCODE_SIGNING_CERTIFICATE );
        LogInfo( ( "Assume Cert - No such file: %s. Using header file", (const char*)pucCertName ) );
    }
    else
    {
        LogInfo( ( "Assume Cert - file: %s OK", (const char*)pucCertName ) );
    }

    /* Allocate memory for the signer certificate plus a terminating zero so we can load it and return to the caller. */
    pucSignerCert = pvPortMalloc( ulCertSize +  1);
    if ( pucSignerCert != NULL )
    {
        memcpy( pucSignerCert, pucCertData, ulCertSize );
        /* The crypto code requires the terminating zero to be part of the length so add 1 to the size. */
        pucSignerCert[ ulCertSize ] = '\0';
        *lSignerCertSize = ulCertSize + 1;
    }
    return pucSignerCert;
}

static OtaPalStatus_t prvSignatureVerificationUpdate_rtl8721d(OtaFileContext_t *C, void * pvContext)
{
    OtaPalMainStatus_t mainErr = OtaPalSuccess;
    OtaPalSubStatus_t subErr = 0;

    u32 i;
    flash_t flash;
    u8 * pTempbuf;
    int rlen;
    u32 len = aws_ota_imgsz;
    u32 addr = ota_ctx.lFileHandle;//aws_ota_target_hdr.FileImgHdr[HdrIdx].FlashAddr;

    if(len <= 0) {
      mainErr = OtaPalSignatureCheckFailed;
      return OTA_PAL_COMBINE_ERR( mainErr, subErr );
    }

    pTempbuf = malloc(BUF_SIZE);
    if(!pTempbuf){
        mainErr = OtaPalSignatureCheckFailed;
        goto error;
    }

    /*handle manifest */
    memcpy(&aws_ota_target_hdr.Manifest[HdrIdx], &aws_manifest, sizeof(update_manifest_info));
    CRYPTO_SignatureVerificationUpdate(pvContext, &aws_ota_target_hdr.Manifest[HdrIdx], sizeof(update_manifest_info));

    printf("[%d]manifest\n",HdrIdx);
    for (int i = 0; i < sizeof(update_manifest_info); i++) {
        printf("0x%x ",*((u8 *)&aws_ota_target_hdr.Manifest[HdrIdx] + i));
    }
    printf("\n");

    len = len - sizeof(update_manifest_info);
    /* read flash data back to check signature of the image */
    for (i = 0; i < len; i += BUF_SIZE) {
        rlen = (len - i) > BUF_SIZE ? BUF_SIZE : (len - i);
        flash_stream_read(&flash, addr - SPI_FLASH_BASE + i + sizeof(update_manifest_info), rlen, pTempbuf);
    #if OTA_MEMDUMP
        vMemDump(addr - SPI_FLASH_BASE + i + sizeof(update_manifest_info), pTempbuf, rlen, "PAYLOAD1");
    #endif
        CRYPTO_SignatureVerificationUpdate(pvContext, pTempbuf, rlen);
    }

error:
    if(pTempbuf)
        free(pTempbuf);

    return OTA_PAL_COMBINE_ERR( mainErr, subErr );
}

OtaPalStatus_t prvPAL_SetPlatformImageState_rtl8721d (OtaImageState_t eState);
OtaPalStatus_t prvPAL_CheckFileSignature_rtl8721d(OtaFileContext_t * const C)
{
    OtaPalMainStatus_t mainErr = OtaPalSuccess;
    OtaPalSubStatus_t subErr = 0;

    int32_t lSignerCertSize;
    void *pvSigVerifyContext;
    uint8_t *pucSignerCert = NULL;

#if (defined(__ICCARM__))
    extern void *calloc_freertos(size_t nelements, size_t elementSize);
    mbedtls_platform_set_calloc_free(calloc_freertos, vPortFree);
#endif

    /* Verify an ECDSA-SHA256 signature. */
    if (CRYPTO_SignatureVerificationStart(&pvSigVerifyContext, cryptoASYMMETRIC_ALGORITHM_ECDSA, cryptoHASH_ALGORITHM_SHA256) == pdFALSE) {
        mainErr = OtaPalSignatureCheckFailed;
        goto exit;
    }

	LogInfo(("[%s] Started %s signature verification, file: %s", __FUNCTION__, OTA_JsonFileSignatureKey, (const char *)C->pCertFilepath));
	if ((pucSignerCert = prvPAL_ReadAndAssumeCertificate_rtl8721d((const uint8_t *const)C->pCertFilepath, &lSignerCertSize)) == NULL) {
		mainErr = OtaPalBadSignerCert;
		goto exit;
	}


	if (OTA_PAL_MAIN_ERR(prvSignatureVerificationUpdate_rtl8721d(C, pvSigVerifyContext)) != OtaPalSuccess) {
		mainErr = OtaPalSignatureCheckFailed;
		goto exit;
	}

	if (CRYPTO_SignatureVerificationFinal(pvSigVerifyContext, (char *)pucSignerCert, lSignerCertSize, C->pSignature->data, C->pSignature->size) == pdFALSE) {
		mainErr = OtaPalSignatureCheckFailed;
		prvPAL_SetPlatformImageState_rtl8721d(OtaImageStateRejected);
		goto exit;
	}

exit:
    /* Free the signer certificate that we now own after prvPAL_ReadAndAssumeCertificate(). */
    if (pucSignerCert != NULL) {
        vPortFree(pucSignerCert);
    }
    return OTA_PAL_COMBINE_ERR(mainErr, subErr);
}

/* Close the specified file. This will also authenticate the file if it is marked as secure. */
OtaPalStatus_t prvPAL_CloseFile_rtl8721d(OtaFileContext_t *C)
{
	OtaPalStatus_t mainErr = OtaPalSuccess;
	OtaPalSubStatus_t subErr = 0;

	LogInfo(("[OTA] Authenticating and closing file.\r\n"));

	if (C == NULL) {
		mainErr = OtaPalNullFileContext;
		goto exit;
	}

	/* close the fw file */
	if (C->pFile) {
		C->pFile = NULL;
	}

	if (C->pSignature != NULL) {
		/* TODO: Verify the file signature, close the file and return the signature verification result. */
		mainErr = OTA_PAL_MAIN_ERR(prvPAL_CheckFileSignature_rtl8721d(C));

	} else {
		mainErr = OtaPalSignatureCheckFailed;
	}

	if (mainErr == OtaPalSuccess) {
		LogInfo(("[%s] %s signature verification passed.", __FUNCTION__, OTA_JsonFileSignatureKey));
	} else {
		LogError(("[%s] Failed to pass %s signature verification: %d.", __FUNCTION__, OTA_JsonFileSignatureKey, mainErr));

		/* If we fail to verify the file signature that means the image is not valid. We need to set the image state to aborted. */
		prvPAL_SetPlatformImageState_rtl8721d(OtaImageStateAborted);
	}

exit:
	return OTA_PAL_COMBINE_ERR(mainErr, subErr);
}

int32_t prvPAL_WriteBlock_rtl8721d(OtaFileContext_t *C, uint32_t ulOffset, uint8_t* pData, uint32_t ulBlockSize)
{
    flash_t flash;
    uint32_t address = ota_ctx.lFileHandle - SPI_FLASH_BASE;
    static uint32_t img_sign = 0;
    uint32_t WriteLen, offset;

    if (aws_ota_target_hdr_get != true)
    {
        u32 RevHdrLen;
        if(ulOffset == 0)
        {
            img_sign = 0;
            memset((void *)&aws_ota_target_hdr, 0, sizeof(update_ota_target_hdr));
            memcpy((u8*)(&aws_ota_target_hdr.FileHdr), pData, sizeof(aws_ota_target_hdr.FileHdr));
            if(aws_ota_target_hdr.FileHdr.HdrNum > 2 || aws_ota_target_hdr.FileHdr.HdrNum <= 0)
            {
                OTA_PRINT("INVALID IMAGE BLOCK 0\r\n");
                return -1;
            }

            memcpy((u8*)(&aws_ota_target_hdr.FileImgHdr[HdrIdx]), pData+sizeof(aws_ota_target_hdr.FileHdr), 8);
            RevHdrLen = (aws_ota_target_hdr.FileHdr.HdrNum * aws_ota_target_hdr.FileImgHdr[HdrIdx].ImgHdrLen) + sizeof(aws_ota_target_hdr.FileHdr);
            if (!prvGet_ota_tartget_header(pData, RevHdrLen, &aws_ota_target_hdr, ota_target_index))
            {
                OTA_PRINT("Get OTA header failed\n");
                return -1;
            }
            aws_ota_target_hdr_get = true;
        }
        else
        {
            aws_ota_target_hdr.FileImgHdr[HdrIdx].ImgLen = ota_ctx.lFileHandle;
            aws_ota_target_hdr.FileHdr.HdrNum = 0x1;
            aws_ota_target_hdr.FileImgHdr[HdrIdx].Offset = 0x20;
        }
    }

    LogInfo(("[%s] C->fileSize %d, iOffset: 0x%x: iBlockSize: 0x%x", __FUNCTION__, C->fileSize, ulOffset, ulBlockSize));

    if(aws_ota_imgsz >= aws_ota_target_hdr.FileImgHdr[HdrIdx].ImgLen){
        OTA_PRINT("[OTA] image download is already done, dropped, aws_ota_imgsz=0x%X, ImgLen=0x%X\n",aws_ota_imgsz,aws_ota_target_hdr.FileImgHdr[aws_ota_target_hdr.FileHdr.HdrNum].ImgLen);
        return ulBlockSize;
    }

    // handle first block, do not write ota header to flash
    if(ulOffset <= aws_ota_target_hdr.FileImgHdr[HdrIdx].Offset) {
        uint32_t byte_to_write = (ulOffset + ulBlockSize) - aws_ota_target_hdr.FileImgHdr[HdrIdx].Offset;

        pData += (ulBlockSize - byte_to_write);

        if(OTA_FILE_BLOCK_SIZE > 0x1000 && ulOffset == 0)
        {
             OTA_PRINT("[OTA] manifest data arrived \n");
             //Save manifest
             memcpy(&aws_manifest, pData, sizeof(update_manifest_info));
             //Erase manifest for protect shutdown while ota downloading
             memset(pData, 0xff, sizeof(update_manifest_info));

             printf("[%d]manifest\n",HdrIdx);
             for (int i = 0; i < sizeof(update_manifest_info); i++) {
                 printf("0x%x ",*((u8 *)&aws_manifest + i));
             }
             printf("\n");
        }

        OTA_PRINT("[OTA] FIRST Write %d bytes @ 0x%x\n", byte_to_write, address);
        if(flash_stream_write(&flash, address, byte_to_write, pData) < 0){
            OTA_PRINT("[%s] Write sector failed\n", __FUNCTION__);
            return -1;
        }
#if OTA_MEMDUMP
        vMemDump(address, pData, byte_to_write, "PAYLOAD1");
#endif
        aws_ota_imgsz += byte_to_write;
        return ulBlockSize;
    }

    // handle manifest
    if(OTA_FILE_BLOCK_SIZE == 0x1000 && ulOffset == 0x1000)
    {
        OTA_PRINT("[OTA] manifest data arrived \n");
        //Save manifest
        memcpy(&aws_manifest, pData+aws_ota_target_hdr.FileImgHdr[HdrIdx].Offset, sizeof(update_manifest_info));
        //Erase manifest for protect shutdown while ota downloading
        memset(pData+aws_ota_target_hdr.FileImgHdr[HdrIdx].Offset, 0xff, sizeof(update_manifest_info));

        printf("[%d]manifest\n",HdrIdx);
        for (int i = 0; i < sizeof(update_manifest_info); i++) {
            printf("0x%x ",*((u8 *)&aws_manifest + i));
        }
        printf("\n");
   }

    WriteLen = ulBlockSize;
    offset = ulOffset - aws_ota_target_hdr.FileImgHdr[HdrIdx].Offset;
    if ((offset + ulBlockSize) >= aws_ota_target_hdr.FileImgHdr[HdrIdx].ImgLen) {

        if(offset > aws_ota_target_hdr.FileImgHdr[HdrIdx].ImgLen)
            return ulBlockSize;
        WriteLen -= (offset + ulBlockSize - aws_ota_target_hdr.FileImgHdr[HdrIdx].ImgLen);
        OTA_PRINT("[OTA] LAST image data arrived %d\n", WriteLen);
    }

    LogInfo( ("[OTA] Write %d bytes @ 0x%x \n", WriteLen, address + offset) );
    if(flash_stream_write(&flash, address + offset, WriteLen, pData) < 0){
        LogInfo( ("[%s] Write sector failed\n", __FUNCTION__) );
        return -1;
    }
#if OTA_MEMDUMP
    vMemDump(address+offset, pData, ulBlockSize, "PAYLOAD2");
#endif
    aws_ota_imgsz += WriteLen;

    return ulBlockSize;
}

OtaPalStatus_t prvPAL_ActivateNewImage_rtl8721d(void)
{
    flash_t flash;
    OTA_PRINT("[OTA] [%s] Download new firmware %d bytes completed @ 0x%x\n", __FUNCTION__, aws_ota_imgsz, aws_ota_imgaddr);
    OTA_PRINT("[OTA] FirmwareSize = %d, OtaTargetHdr.FileImgHdr.ImgLen = %d\n", aws_ota_imgsz, aws_ota_target_hdr.FileImgHdr[HdrIdx].ImgLen);

    /*------------- verify checksum and update signature-----------------*/
    if(verify_ota_checksum(&aws_ota_target_hdr, ota_target_index, 0/*header index*/)){
        if(!ota_update_manifest(&aws_ota_target_hdr, ota_target_index, 0/*header index*/)) {
            OTA_PRINT("[OTA] [%s], change signature failed\r\n", __FUNCTION__);
            return OTA_PAL_COMBINE_ERR( OtaPalActivateFailed, 0 );
        } else {
            flash_erase_sector(&flash, AWS_OTA_IMAGE_STATE_FLASH_OFFSET);
            flash_write_word(&flash, AWS_OTA_IMAGE_STATE_FLASH_OFFSET, AWS_OTA_IMAGE_STATE_FLAG_PENDING_COMMIT);
            OTA_PRINT("[OTA] [%s] Update OTA success!\r\n", __FUNCTION__);
        }
    }else{
        /*if checksum error, clear the signature zone which has been written in flash in case of boot from the wrong firmware*/
        flash_erase_sector(&flash, aws_ota_imgaddr - SPI_FLASH_BASE);
        OTA_PRINT("[OTA] [%s] The checksume is wrong!\n\r", __FUNCTION__);
        return OTA_PAL_COMBINE_ERR( OtaPalActivateFailed, 0 );
    }
    LogInfo( ("[OTA] Resetting MCU to activate new image.\r\n") );
    vTaskDelay( 500 );
    prvSysReset_rtl8721d(10);
    return OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0 );
}

OtaPalStatus_t prvPAL_ResetDevice_rtl8721d ( void )
{
    prvSysReset_rtl8721d(10);
    return OTA_PAL_COMBINE_ERR( OtaPalSuccess, 0 );
}

OtaPalStatus_t prvPAL_SetPlatformImageState_rtl8721d (OtaImageState_t eState)
{
    OtaPalMainStatus_t mainErr = OtaPalSuccess;
    OtaPalSubStatus_t subErr = 0;
    flash_t flash;

	if ((eState != OtaImageStateUnknown) && (eState <= OtaLastImageState)) {
		/* write state to file */
		flash_erase_sector(&flash, AWS_OTA_IMAGE_STATE_FLASH_OFFSET);
		flash_write_word(&flash, AWS_OTA_IMAGE_STATE_FLASH_OFFSET, eState);
	} else { /* Image state invalid. */
		LogError(("[%s] Invalid image state provided.", __FUNCTION__));
		mainErr = OtaPalBadImageState;
	}

	return OTA_PAL_COMBINE_ERR(mainErr, subErr);
}

OtaPalImageState_t prvPAL_GetPlatformImageState_rtl8721d( void )
{
    OtaPalImageState_t eImageState = OtaPalImageStateUnknown;
    uint32_t eSavedAgentState  =  OtaImageStateUnknown;
    flash_t flash;

    flash_read_word(&flash, AWS_OTA_IMAGE_STATE_FLASH_OFFSET, &eSavedAgentState );

    switch ( eSavedAgentState  )
    {
        case OtaImageStateTesting:
            /* Pending Commit means we're in the Self Test phase. */
            eImageState = OtaPalImageStatePendingCommit;
            break;
        case OtaImageStateAccepted:
            eImageState = OtaPalImageStateValid;
            break;
        case OtaImageStateRejected:
        case OtaImageStateAborted:
        default:
            eImageState = OtaPalImageStateInvalid;
            break;
    }
    LogInfo( ( "Image current state (0x%02x).", eImageState ) );

    return eImageState;
}

u8 * prvReadAndAssumeCertificate_rtl8721d(const u8 * const pucCertName, s32 * const lSignerCertSize)
{
    LogInfo( ("prvReadAndAssumeCertificate: not implemented yet\r\n") );
    return NULL;
}

