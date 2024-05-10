/*
 * FreeRTOS PKCS #11 PAL V1.0.0
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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

/**
 * @file core_pkcs11_pal.c
 * @brief Device specific helpers for PKCS11 Interface.
 */

/* FreeRTOS Includes. */
#include "core_pkcs11.h"
#include "core_pkcs11_config.h"
#include "FreeRTOS.h"

/* C runtime includes. */
#include <stdio.h>
#include <string.h>

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "flash_api.h"
#include "platform_stdlib.h"
#include "amazon/example_amazon_freertos.h"

#define pkcs11OBJECT_CERTIFICATE_MAX_SIZE    4096
#define pkcs11OBJECT_FLASH_CERT_PRESENT      ( 0x22ABCDEFuL ) //magic number for check flash data
#if 0 // move to example_amazon_freertos.h
#define pkcs11OBJECT_CERT_FLASH_OFFSET       ( 0x1DC000 ) //Flash location for CERT
#define pkcs11OBJECT_PRIV_KEY_FLASH_OFFSET   ( 0x1DD000 ) //Flash location for Priv Key
#define pkcs11OBJECT_PUB_KEY_FLASH_OFFSET    ( 0x1DE000 ) //Flash location for Pub Key
#define pkcs11OBJECT_VERIFY_KEY_FLASH_OFFSET ( 0x1DF000 ) //Flash location for code verify Key
#endif
/*
 * Flash Format
 * | Flash Mark(4) | checksum(4) | DataLen(4) |  Data |
 */
#define FLASH_SECTOR_SIZE      0x1000
#define FLASH_CHECKSUM_OFFSET  4
#define FLASH_DATALEN_OFFSET   8
#define FLASH_DATA_OFFSET     12

enum eObjectHandles
{
    eInvalidHandle = 0, /* According to PKCS #11 spec, 0 is never a valid object handle. */
    eAwsDevicePrivateKey = 1,
    eAwsDevicePublicKey,
    eAwsDeviceCertificate,
    eAwsCodeSigningKey
};

void prvLabelToFlashAddrHandle( uint8_t * pcLabel,
                               uint32_t * pcFlashAddress,
                               CK_OBJECT_HANDLE_PTR pHandle )
{
    if( pcLabel != NULL )
    {
        /* Translate from the PKCS#11 label to local storage file name. */
        if( 0 == memcmp( pcLabel,
                         &pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                         sizeof( pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS ) ) )
        {
            *pcFlashAddress = pkcs11OBJECT_CERT_FLASH_OFFSET;
            *pHandle = eAwsDeviceCertificate;
        }
        else if( 0 == memcmp( pcLabel,
                              &pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                              sizeof( pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS ) ) )
        {
        	*pcFlashAddress = pkcs11OBJECT_PRIV_KEY_FLASH_OFFSET;
            *pHandle = eAwsDevicePrivateKey;
        }
        else if( 0 == memcmp( pcLabel,
                              &pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                              sizeof( pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS ) ) )
        {
        	*pcFlashAddress = pkcs11OBJECT_PUB_KEY_FLASH_OFFSET;
            *pHandle = eAwsDevicePublicKey;
        }
        else if( 0 == memcmp( pcLabel,
                              &pkcs11configLABEL_CODE_VERIFICATION_KEY,
                              sizeof( pkcs11configLABEL_CODE_VERIFICATION_KEY ) ) )
        {
        	*pcFlashAddress = pkcs11OBJECT_VERIFY_KEY_FLASH_OFFSET;
            *pHandle = eAwsCodeSigningKey;
        }
        else
        {
            *pcFlashAddress = 0;
            *pHandle = eInvalidHandle;
        }
    }
}

/**
 * @brief Initializes the PKCS #11 PAL.
 *
 * @return CKR_OK on success.
 * CKR_FUNCTION_FAILED on failure.
 */
CK_RV PKCS11_PAL_Initialize( void )
{
    CK_RV xReturn = CKR_OK;
    return xReturn;
}

/**
* @brief Writes a file to local storage.
*
* Port-specific file write for crytographic information.
*
* @param[in] pxLabel       Label of the object to be saved.
* @param[in] pucData       Data buffer to be written to file
* @param[in] ulDataSize    Size (in bytes) of data to be saved.
*
* @return The file handle of the object that was stored.
*/
CK_OBJECT_HANDLE PKCS11_PAL_SaveObject( CK_ATTRIBUTE_PTR pxLabel,
                                        CK_BYTE_PTR pucData,
                                        CK_ULONG ulDataSize )
{
    CK_OBJECT_HANDLE xHandle = eInvalidHandle;
	uint32_t pcFlashAddr;
	CK_RV xBytesWritten = 0;
	CK_ULONG ulFlashMark = pkcs11OBJECT_FLASH_CERT_PRESENT;
	CK_ULONG ulCheckSum = 0;
	CK_ULONG i;
	flash_t flash;

	/* Converts a label to its respective flash address and handle. */
	prvLabelToFlashAddrHandle( pxLabel->pValue, &pcFlashAddr, &xHandle );

	if(xHandle != eInvalidHandle){
		xBytesWritten = ( ulDataSize );
		if( xBytesWritten <= (FLASH_SECTOR_SIZE - FLASH_DATALEN_OFFSET - 4)  )
		{
			ulCheckSum = 0;
			for( i = 0; i < xBytesWritten; i++)
				ulCheckSum += pucData[i];

			flash_erase_sector(&flash, pcFlashAddr);
			flash_write_word(&flash, pcFlashAddr, ulFlashMark);
			flash_write_word(&flash, pcFlashAddr + FLASH_CHECKSUM_OFFSET, ulCheckSum);
			flash_write_word(&flash, pcFlashAddr + FLASH_DATALEN_OFFSET, xBytesWritten);
			flash_stream_write(&flash, pcFlashAddr + FLASH_DATA_OFFSET, xBytesWritten, pucData);
			flash_write_word(&flash, pcFlashAddr + FLASH_DATA_OFFSET + xBytesWritten, 0x0); // include '\0'
		}
	}
    return xHandle;
}

/**
* @brief Translates a PKCS #11 label into an object handle.
*
* Port-specific object handle retrieval.
*
*
* @param[in] pxLabel         Pointer to the label of the object
*                           who's handle should be found.
* @param[in] usLength       The length of the label, in bytes.
*
* @return The object handle if operation was successful.
* Returns eInvalidHandle if unsuccessful.
*/
CK_OBJECT_HANDLE PKCS11_PAL_FindObject( CK_BYTE_PTR pxLabel,
                                        CK_ULONG usLength )
{
	/* Avoid compiler warnings about unused variables. */
	( void ) usLength;

    CK_OBJECT_HANDLE xHandle = 0;
	uint32_t pcFlashAddr = 0;
	flash_t flash;
	CK_ULONG ulFlashMark;

	/* Converts a label to its respective flash address and handle. */
	prvLabelToFlashAddrHandle( pxLabel, &pcFlashAddr, &xHandle);

	/* Check if object exists/has been created before returning. */
	if(xHandle != eInvalidHandle)
	{
		flash_read_word(&flash, pcFlashAddr, &ulFlashMark);
		if( ulFlashMark != pkcs11OBJECT_FLASH_CERT_PRESENT ){
			xHandle = eInvalidHandle;
		}
	}

    return xHandle;
}

/**
* @brief Gets the value of an object in storage, by handle.
*
* Port-specific file access for cryptographic information.
*
* This call dynamically allocates the buffer which object value
* data is copied into.  PKCS11_PAL_GetObjectValueCleanup()
* should be called after each use to free the dynamically allocated
* buffer.
*
* @sa PKCS11_PAL_GetObjectValueCleanup
*
* @param[in] pcFileName    The name of the file to be read.
* @param[out] ppucData     Pointer to buffer for file data.
* @param[out] pulDataSize  Size (in bytes) of data located in file.
* @param[out] pIsPrivate   Boolean indicating if value is private (CK_TRUE)
*                          or exportable (CK_FALSE)
*
* @return CKR_OK if operation was successful.  CKR_KEY_HANDLE_INVALID if
* no such object handle was found, CKR_DEVICE_MEMORY if memory for
* buffer could not be allocated, CKR_FUNCTION_FAILED for device driver
* error.
*/
CK_RV PKCS11_PAL_GetObjectValue( CK_OBJECT_HANDLE xHandle,
                                      CK_BYTE_PTR * ppucData,
                                      CK_ULONG_PTR pulDataSize,
                                      CK_BBOOL * pIsPrivate )
{
    CK_RV xReturn = CKR_OK;
	uint32_t pcFlashAddr = 0;

	CK_ULONG ulFlashMark;
	CK_ULONG ulCheckSum = 0, ulTemp;
	CK_ULONG i;
	flash_t flash;

    switch(xHandle)
    {
		case eAwsDeviceCertificate:
			pcFlashAddr = pkcs11OBJECT_CERT_FLASH_OFFSET;
			*pIsPrivate = CK_FALSE;
			break;
		case eAwsDevicePrivateKey:
			pcFlashAddr = pkcs11OBJECT_PRIV_KEY_FLASH_OFFSET;
			*pIsPrivate = CK_TRUE;
			break;
		case eAwsDevicePublicKey:
			pcFlashAddr = pkcs11OBJECT_PUB_KEY_FLASH_OFFSET;
			*pIsPrivate = CK_FALSE;
			break;
		case eAwsCodeSigningKey:
			pcFlashAddr = pkcs11OBJECT_VERIFY_KEY_FLASH_OFFSET;
			*pIsPrivate = CK_FALSE;
			break;
		default:
			xReturn = CKR_KEY_HANDLE_INVALID;
			break;
    }

	if( pcFlashAddr != 0 )
	{
		flash_read_word(&flash, pcFlashAddr, &ulFlashMark);
		if( ulFlashMark == pkcs11OBJECT_FLASH_CERT_PRESENT )
		{
			*ppucData = pvPortMalloc(pkcs11OBJECT_CERTIFICATE_MAX_SIZE + 1);
			if( *ppucData == NULL )
			{
				xReturn = CKR_DEVICE_MEMORY;
				goto exit;
			}

			flash_read_word(&flash, pcFlashAddr + FLASH_CHECKSUM_OFFSET, &ulCheckSum);
			flash_read_word(&flash, pcFlashAddr + FLASH_DATALEN_OFFSET, pulDataSize);
			flash_stream_read(&flash, pcFlashAddr + FLASH_DATA_OFFSET, pkcs11OBJECT_CERTIFICATE_MAX_SIZE, *ppucData);

			ulTemp = 0;
			for( i = 0; i < *pulDataSize; i++ )
				ulTemp += (*ppucData)[i];
			if( ulTemp != ulCheckSum )
			{
				vPortFree(*ppucData);
				*ppucData = NULL;
				xReturn = CKR_FUNCTION_FAILED;
			} else {
				xReturn = CKR_OK;
			}
		}else{
			xReturn = CKR_KEY_HANDLE_INVALID;
		}
	}

exit:
    return xReturn;
}

/**
* @brief Cleanup after PKCS11_GetObjectValue().
*
* @param[in] pucData       The buffer to free.
*                          (*ppucData from PKCS11_PAL_GetObjectValue())
* @param[in] ulDataSize    The length of the buffer to free.
*                          (*pulDataSize from PKCS11_PAL_GetObjectValue())
*/
void PKCS11_PAL_GetObjectValueCleanup( CK_BYTE_PTR pucData,
                                       CK_ULONG ulDataSize )
{
    /* Unused parameters. */
	( void ) ulDataSize;

	if( pucData )
		vPortFree( pucData );
}

/* Converts a handle to its respective label. */
void prvHandleToLabel( char ** pcLabel,
                       CK_OBJECT_HANDLE xHandle )
{
    if( pcLabel != NULL )
    {
        switch( xHandle )
        {
            case eAwsDeviceCertificate:
                *pcLabel = ( char * ) pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS;
                break;

            case eAwsDevicePrivateKey:
                *pcLabel = ( char * ) pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS;
                break;

            case eAwsDevicePublicKey:
                *pcLabel = ( char * ) pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS;
                break;

            case eAwsCodeSigningKey:
                *pcLabel = ( char * ) pkcs11configLABEL_CODE_VERIFICATION_KEY;
                break;

            default:
                *pcLabel = NULL;
                break;
        }
    }
}

CK_RV PKCS11_PAL_DestroyObject( CK_OBJECT_HANDLE xHandle )
{
    CK_RV xResult = CKR_OK;
    CK_BYTE_PTR pxZeroedData = NULL;
    CK_BYTE_PTR pxObject = NULL;
    CK_BBOOL xIsPrivate = ( CK_BBOOL ) CK_TRUE;
    CK_OBJECT_HANDLE xPalHandle2 = CK_INVALID_HANDLE;
    CK_ULONG ulObjectLength = sizeof( CK_BYTE );
    char * pcLabel = NULL;
    CK_ATTRIBUTE xLabel;

    prvHandleToLabel( &pcLabel, xHandle );

    if( pcLabel != NULL )
    {
        xLabel.type = CKA_LABEL;
        xLabel.pValue = pcLabel;
        xLabel.ulValueLen = strlen( pcLabel );

        xResult = PKCS11_PAL_GetObjectValue( xHandle, &pxObject, &ulObjectLength, &xIsPrivate );
    }
    else
    {
        xResult = CKR_OBJECT_HANDLE_INVALID;
    }

    if( xResult == CKR_OK )
    {
        /* Some ports return a pointer to memory for which using memset directly won't work. */
        pxZeroedData = pvPortMalloc( ulObjectLength * sizeof( CK_BYTE ) );

        if( NULL != pxZeroedData )
        {
            /* Zero out the object. */
            ( void ) memset( pxZeroedData, 0x0, ulObjectLength );
            /* Create an object label attribute. */
            /* Overwrite the object in NVM with zeros. */
            xPalHandle2 = PKCS11_PAL_SaveObject( &xLabel, pxZeroedData, ( size_t ) ulObjectLength );

            if( xPalHandle2 != xHandle )
            {
                xResult = CKR_GENERAL_ERROR;
            }

            vPortFree( pxZeroedData );
        }
        else
        {
            xResult = CKR_HOST_MEMORY;
        }

        PKCS11_PAL_GetObjectValueCleanup( pxObject, ulObjectLength );
    }

    return xResult;
}

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
extern int TRNG_get_random_bytes(void* dst, u32 size);
int mbedtls_hardware_poll( void * data,
                           unsigned char * output,
                           size_t len,
                           size_t * olen )
{
    TRNG_get_random_bytes(output, len);
    *olen = len;

    return 0;
}
#endif
