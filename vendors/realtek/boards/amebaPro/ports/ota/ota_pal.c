/*
 * FreeRTOS OTA PAL for Example Vendor port V2.0.0
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/* C Runtime includes. */
#include <stdio.h>
#include <stdlib.h>

/* FreeRTOS include. */
#include "FreeRTOS.h"

/* OTA library includes. */
#include "ota.h"
#include "ota_private.h"

/* OTA PAL Port include. */
#include "ota_pal.h"

/* OTA PAL test config file include. */
#include "ota_config.h"

/* Specify the OTA signature algorithm we support on this platform. */
const char OTA_JsonFileSignatureKey[ OTA_FILE_SIG_KEY_STR_MAX_LENGTH ] = "sig-sha256-ecdsa";   /* FIX ME. */


/* The static functions below (otaPAL_CheckFileSignature and otaPAL_ReadAndAssumeCertificate)
 * are optionally implemented. If these functions are implemented then please set the following
 * macros in aws_test_ota_config.h to 1:
 *   otatestpalCHECK_FILE_SIGNATURE_SUPPORTED
 *   otatestpalREAD_AND_ASSUME_CERTIFICATE_SUPPORTED
 */

/**
 * @brief Verify the signature of the specified file.
 *
 * This function should be implemented if signature verification is not offloaded to non-volatile
 * memory io functions.
 *
 * This function is expected to be called from otaPal_CloseFile().
 *
 * @param[in] pFileContext OTA file context information.
 *
 * @return The OtaPalStatus_t error code combined with the MCU specific error code. See
 *         ota_platform_interface.h for OTA major error codes and your specific PAL implementation
 *         for the sub error code.
 *
 * Major error codes returned are:
 *   OtaPalSuccess: if the signature verification passes.
 *   OtaPalSignatureCheckFailed: if the signature verification fails.
 *   OtaPalBadSignerCert: if the signature verification certificate cannot be read.
 */
static OtaPalStatus_t otaPal_CheckFileSignature( OtaFileContext_t * const pFileContext );

/**
 * @brief Read the specified signer certificate from the filesystem into a local buffer.
 *
 * The allocated memory returned becomes the property of the caller who is responsible for freeing it.
 *
 * This function is called from otaPAL_CheckFileSignature(). It should be implemented if signature
 * verification is not offloaded to non-volatile memory io function.
 *
 * @param[in] pucCertName The file path of the certificate file.
 * @param[out] ulSignerCertSize The size of the certificate file read.
 *
 * @return A pointer to the signer certificate in the file system. NULL if the certificate cannot be read.
 * This returned pointer is the responsibility of the caller; if the memory is allocated the caller must free it.
 */
static uint8_t * otaPal_ReadAndAssumeCertificate( const uint8_t * const pucCertName,
                                                  uint32_t * const ulSignerCertSize );


/*-----------------------------------------------------------*/

#if defined(CONFIG_PLATFORM_8711B)
OtaPalStatus_t prvPAL_Abort_rtl8710b(OtaFileContext_t *C);
OtaPalStatus_t prvPAL_CreateFileForRx_rtl8710b(OtaFileContext_t *C);
OtaPalStatus_t prvPAL_CloseFile_rtl8710b(OtaFileContext_t *C);
int16_t prvPAL_WriteBlock_rtl8710b(OtaFileContext_t *C, int32_t iOffset, uint8_t* pacData, uint32_t iBlockSize);
OtaPalStatus_t prvPAL_ActivateNewImage_rtl8710b(void);
OtaPalStatus_t prvPAL_SetPlatformImageState_rtl8710b (OtaImageState_t eState);
OtaPalImageState_t prvPAL_GetPlatformImageState_rtl8710b( void );
#elif defined(CONFIG_PLATFORM_8721D)
OtaPalStatus_t prvPAL_Abort_rtl8721d(OtaFileContext_t *C);
OtaPalStatus_t prvPAL_CreateFileForRx_rtl8721d(OtaFileContext_t *C);
OtaPalStatus_t prvPAL_CloseFile_rtl8721d(OtaFileContext_t *C);
OtaPalStatus_t prvPAL_CheckFileSignature_rtl8721d(OtaFileContext_t * const C);
int16_t prvPAL_WriteBlock_rtl8721d(OtaFileContext_t *C, int32_t iOffset, uint8_t* pacData, uint32_t iBlockSize);
OtaPalStatus_t prvPAL_ActivateNewImage_rtl8721d(void);
OtaPalStatus_t prvPAL_SetPlatformImageState_rtl8721d (OtaImageState_t eState);
OtaPalImageState_t prvPAL_GetPlatformImageState_rtl8721d( void );
#elif defined(CONFIG_PLATFORM_8710C)
OtaPalStatus_t prvPAL_Abort_amebaZ2(OtaFileContext_t *C);
OtaPalStatus_t prvPAL_CreateFileForRx_amebaZ2(OtaFileContext_t *C);
OtaPalStatus_t prvPAL_CloseFile_amebaZ2(OtaFileContext_t *C);
int16_t prvPAL_WriteBlock_amebaZ2(OtaFileContext_t *C, int32_t iOffset, uint8_t* pacData, uint32_t iBlockSize);
OtaPalStatus_t prvPAL_ActivateNewImage_amebaZ2(void);
OtaPalStatus_t prvPAL_SetPlatformImageState_amebaZ2 (OtaImageState_t eState);
OtaPalImageState_t prvPAL_GetPlatformImageState_amebaZ2( void );
#elif defined(CONFIG_PLATFORM_8195B) /* AmebaPro */
OtaPalStatus_t prvPAL_Abort_amebaPro(OtaFileContext_t *C);
OtaPalStatus_t prvPAL_CreateFileForRx_amebaPro(OtaFileContext_t *C);
OtaPalStatus_t prvPAL_CloseFile_amebaPro(OtaFileContext_t *C);
int16_t prvPAL_WriteBlock_amebaPro(OtaFileContext_t *C, int32_t iOffset, uint8_t* pacData, uint32_t iBlockSize);
OtaPalStatus_t prvPAL_ActivateNewImage_amebaPro(void);
OtaPalStatus_t prvPAL_SetPlatformImageState_amebaPro (OtaImageState_t eState);
OtaPalImageState_t prvPAL_GetPlatformImageState_amebaPro( void );
#else
#error "This platform is not supported!"
#endif

OtaPalStatus_t otaPal_Abort( OtaFileContext_t * const pFileContext )
{
    LogInfo( ( "%s", __func__ ) );
    return prvPAL_Abort_amebaPro(pFileContext);
}

/*-----------------------------------------------------------*/

OtaPalStatus_t otaPal_CreateFileForRx( OtaFileContext_t * const pFileContext )
{
    LogInfo( ( "%s", __func__ ) );
    return prvPAL_CreateFileForRx_amebaPro(pFileContext) == pdTRUE?OtaPalSuccess:OtaPalRxFileCreateFailed;
}

/*-----------------------------------------------------------*/

OtaPalStatus_t otaPal_CloseFile( OtaFileContext_t * const pFileContext )
{
    LogInfo( ( "%s", __func__ ) );
    return prvPAL_CloseFile_amebaPro(pFileContext);
}

/*-----------------------------------------------------------*/

int16_t otaPal_WriteBlock( OtaFileContext_t * const pFileContext,
                           uint32_t ulOffset,
                           uint8_t * const pData,
                           uint32_t ulBlockSize )
{
    LogInfo( ( "%s", __func__ ) );
    return prvPAL_WriteBlock_amebaPro(pFileContext, ulOffset, pData, ulBlockSize);
}

/*-----------------------------------------------------------*/

OtaPalStatus_t otaPal_ActivateNewImage( OtaFileContext_t * const pFileContext )
{
    LogInfo( ( "%s", __func__ ) );
    return prvPAL_ActivateNewImage_amebaPro();
}

/*-----------------------------------------------------------*/

OtaPalStatus_t otaPal_SetPlatformImageState( OtaFileContext_t * const pFileContext,
                                             OtaImageState_t eState )
{
    LogInfo( ( "%s", __func__ ) );
    return prvPAL_SetPlatformImageState_amebaPro(eState);
}

/*-----------------------------------------------------------*/

OtaPalImageState_t otaPal_GetPlatformImageState( OtaFileContext_t * const pFileContext )
{
    LogInfo( ( "%s", __func__ ) );
    return prvPAL_GetPlatformImageState_amebaPro();
}

/*-----------------------------------------------------------*/

OtaPalStatus_t otaPal_ResetDevice( OtaFileContext_t * const pFileContext )
{
    LogInfo( ( "%s", __func__ ) );
    return prvPAL_ResetDevice_amebaPro();
}

/*-----------------------------------------------------------*/

static OtaPalStatus_t otaPal_CheckFileSignature( OtaFileContext_t * const pFileContext )
{
    LogInfo( ( "%s", __func__ ) );
    return prvPAL_CheckFileSignature_amebaPro(pFileContext);
}

/*-----------------------------------------------------------*/

static uint8_t * otaPal_ReadAndAssumeCertificate( const uint8_t * const pucCertName,
                                                  uint32_t * const ulSignerCertSize )
{
    LogInfo( ( "%s", __func__ ) );
    return (uint8_t *) prvPAL_ReadAndAssumeCertificate_amebaPro( pucCertName, ulSignerCertSize);
}

/*-----------------------------------------------------------*/

/* Provide access to private members for testing. */
#ifdef FREERTOS_ENABLE_UNIT_TESTS
    #include "aws_ota_pal_test_access_define.h"
#endif