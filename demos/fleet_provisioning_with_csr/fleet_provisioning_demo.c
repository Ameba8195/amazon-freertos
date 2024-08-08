/*
 * FreeRTOS V202012.00
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
 * http://www.FreeRTOS.org
 * http://aws.amazon.com/freertos
 *
 */

/*
 * Demo for showing use of the MQTT API using Fleet Provisioning by Claim API.
 *
 * The Example shown below uses MQTT APIs to create CSR and send them
 * over the mutually authenticated network connection established with the
 * MQTT broker. This example is single threaded and uses statically allocated
 * memory. It uses QoS1 for sending to and receiving messages from the broker.
 *
 * A mutually authenticated TLS connection is used to connect to the
 * MQTT message broker in this example. Define democonfigMQTT_BROKER_ENDPOINT
 * and democonfigROOT_CA_PEM, in mqtt_demo_mutual_auth_config.h, and the client
 * private key and certificate, in aws_clientcredential_keys.h, to establish a
 * mutually authenticated connection.
 */

/**
 * @file fleet_provisioning_csr.c
 * @brief Demonstrates usage of the MQTT library.
 */

/* Standard includes. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Demo Specific configs. */
#include "fleet_provisioning_config.h"

/* AWS IoT Fleet Provisioning Library. */
#include "fleet_provisioning.h"

/* Include common demo header. */
#include "aws_demo.h"

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"

/* MQTT library includes. */
#include "core_mqtt.h"

/* Retry utilities include. */
#include "backoff_algorithm.h"

/* Include PKCS11 helpers header. */
#include "pkcs11_helpers.h"

#include "pkcs11_operations.h"

/* Transport interface implementation include header for TLS. */
#include "transport_secure_sockets.h"

/* Include header for connection configurations. */
#include "aws_clientcredential.h"

/* Include header for client credentials. */
#include "aws_clientcredential_keys.h"

/* Include header for root CA certificates. */
#include "iot_default_root_certificates.h"

/* TinyCBOR library for CBOR encoding and decoding operations. */
#include "cbor.h"

/* Demo includes. */
#include "tinycbor_serializer.h"

/* corePKCS11 includes. */
#include "core_pkcs11.h"
#include "core_pkcs11_config.h"

/* aws_dev_mode_key_provisioning includes */
#include "aws_dev_mode_key_provisioning.h"

/*------------- Demo configurations -------------------------*/

/** Note: The device client certificate and private key credentials are
 * obtained by the transport interface implementation (with Secure Sockets)
 * from the demos/include/aws_clientcredential_keys.h file.
 *
 * The following macros SHOULD be defined for this demo which uses both server
 * and client authentications for TLS session:
 *   - keyCLIENT_CERTIFICATE_PEM for Fleet provisioning claim CSR certificate.
 *   - keyCLIENT_PRIVATE_KEY_PEM for Fleet provisioning client private key.
 */

/**
 * @brief The length of #democonfigPROVISIONING_TEMPLATE_NAME.
 */

#define democonfigPROVISIONING_TEMPLATE_NAME    "" //Fill in Fleet provisioning template name

#define fpdemoPROVISIONING_TEMPLATE_NAME_LENGTH    ( ( uint16_t ) ( sizeof( democonfigPROVISIONING_TEMPLATE_NAME ) - 1 ) )

#define fpdemoMAX_THING_NAME_LENGTH                128

/**
 * @brief The MQTT broker endpoint used for this demo.
 */
#ifndef democonfigMQTT_BROKER_ENDPOINT
    #define democonfigMQTT_BROKER_ENDPOINT    clientcredentialMQTT_BROKER_ENDPOINT
#endif

#ifndef democonfigCLIENT_IDENTIFIER

/**
 * @brief The MQTT client identifier used in this example.  Each client identifier
 * must be unique so edit as required to ensure no two clients connecting to the
 * same broker use the same client identifier.
 */
    #define democonfigCLIENT_IDENTIFIER    clientcredentialIOT_THING_NAME
#endif

#ifndef democonfigMQTT_BROKER_PORT

/**
 * @brief The port to use for the demo.
 */
    #define democonfigMQTT_BROKER_PORT    clientcredentialMQTT_BROKER_PORT
#endif

/**
 * @brief The root CA certificate belonging to the broker.
 */
#ifndef democonfigROOT_CA_PEM
    #define democonfigROOT_CA_PEM    tlsATS1_ROOT_CERTIFICATE_PEM
#endif

/**
 * @brief The maximum number of times to run the subscribe publish loop in this
 * demo.
 */
#ifndef democonfigMQTT_MAX_DEMO_COUNT
    #define democonfigMQTT_MAX_DEMO_COUNT    ( 3 )
#endif

/**
 * @brief The maximum number of retries for network operation with server.
 */
#define RETRY_MAX_ATTEMPTS                                ( 5U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying failed operation
 *  with server.
 */
#define RETRY_MAX_BACKOFF_DELAY_MS                        ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for network operation retry
 * attempts.
 */
#define RETRY_BACKOFF_BASE_MS                             ( 500U )

/**
 * @brief Timeout for receiving CONNACK packet in milliseconds.
 */
#define CONNACK_RECV_TIMEOUT_MS                ( 1000U )


/**
 * @brief The number of topic filters to subscribe.
 */
#define mqttexampleTOPIC_COUNT                            ( 1 )


/**
 * @brief Time in ticks to wait between each cycle of the demo implemented
 * by RunCoreMqttMutualAuthDemo().
 */
#define mqttexampleDELAY_BETWEEN_DEMO_ITERATIONS_TICKS    ( pdMS_TO_TICKS( 5000U ) )

/**
 * @brief Timeout for MQTT_ProcessLoop in milliseconds.
 */
#define mqttexamplePROCESS_LOOP_TIMEOUT_MS                ( 700U )

/**
 * @brief The maximum number of times to call MQTT_ProcessLoop() when polling
 * for a specific packet from the broker.
 */
#define MQTT_PROCESS_LOOP_PACKET_WAIT_COUNT_MAX           ( 30U )

/**
 * @brief Keep alive time reported to the broker while establishing
 * an MQTT connection.
 *
 * It is the responsibility of the Client to ensure that the interval between
 * Control Packets being sent does not exceed the this Keep Alive value. In the
 * absence of sending any other Control Packets, the Client MUST send a
 * PINGREQ Packet.
 */
#define mqttexampleKEEP_ALIVE_TIMEOUT_SECONDS             ( 60U )

/**
 * @brief Delay (in ticks) between consecutive cycles of MQTT publish operations in a
 * demo iteration.
 *
 * Note that the process loop also has a timeout, so the total time between
 * publishes is the sum of the two delays.
 */
#define mqttexampleDELAY_BETWEEN_PUBLISHES_TICKS          ( pdMS_TO_TICKS( 2000U ) )

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS         ( 500U )

/**
 * @brief Milliseconds per second.
 */
#define MILLISECONDS_PER_SECOND                           ( 1000U )

/**
 * @brief Milliseconds per FreeRTOS tick.
 */
#define MILLISECONDS_PER_TICK                             ( MILLISECONDS_PER_SECOND / configTICK_RATE_HZ )

/**
 * @brief Size of buffer in which to hold the certificate signing request (CSR).
 */
#define fpdemoCSR_BUFFER_LENGTH                              2048

/**
 * @brief Size of the network buffer for MQTT packets. Must be large enough to
 * hold the GetCertificateFromCsr response, which, among other things, includes
 * a PEM encoded certificate.
 */
#define democonfigNETWORK_BUFFER_SIZE                       ( 2048U )

/**
 * @brief Size of buffer in which to hold the certificate.
 */
#define fpdemoCERT_BUFFER_LENGTH                             2048

/**
 * @brief Size of buffer in which to hold the certificate id.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_Certificate.html#iot-Type-Certificate-certificateId
 */
#define fpdemoCERT_ID_BUFFER_LENGTH                          64

/**
 * @brief Size of buffer in which to hold the certificate ownership token.
 */
#define fpdemoOWNERSHIP_TOKEN_BUFFER_LENGTH                  512

/**
 * @brief Buffer to hold the provisioned AWS IoT Thing name.
 */
static char pcThingName[ fpdemoMAX_THING_NAME_LENGTH ];

/**
 * @brief Length of the AWS IoT Thing name.
 */
static size_t xThingNameLength;

 /**
 * @brief The length of #democonfigFP_DEMO_ID.
 */
#define fpdemoFP_DEMO_ID_LENGTH                    ( ( uint16_t ) ( sizeof( democonfigFP_DEMO_ID ) - 1 ) )


#define fpdemoCSR_BUFFER_LENGTH 2048

/**
 * @brief Status values of the Fleet Provisioning response.
 */
typedef enum
{
    ResponseNotReceived,
    ResponseAccepted,
    ResponseRejected
} ResponseStatus_t;

/**
 * @brief Application callback type to handle the incoming publishes.
 *
 * @param[in] pxPublishInfo Pointer to publish info of the incoming publish.
 * @param[in] usPacketIdentifier Packet identifier of the incoming publish.
 */
typedef void (* MQTTPublishCallback_t )( MQTTPublishInfo_t * pxPublishInfo,
                                         uint16_t usPacketIdentifier );

/*-----------------------------------------------------------*/

/**
 * @brief Status reported from the MQTT publish callback.
 */
//static ResponseStatus_t xResponseStatus;

/**
 * @brief Buffer to hold responses received from the AWS IoT Fleet Provisioning
 * APIs. When the MQTT publish callback receives an expected Fleet Provisioning
 * accepted payload, it copies it into this buffer.
 */
static uint8_t pucPayloadBuffer[ democonfigNETWORK_BUFFER_SIZE ];

/**
 * @brief Static buffer used to hold MQTT messages being sent and received.
 */
static uint8_t ucSharedBuffer[ democonfigNETWORK_BUFFER_SIZE ];

/**
 * @brief Global entry time into the application to use as a reference timestamp
 * in the #prvGetTimeMs function. #prvGetTimeMs will always return the difference
 * between the current time and the global entry time. This will reduce the chances
 * of overflow for the 32 bit unsigned integer used for holding the timestamp.
 */
static uint32_t ulGlobalEntryTimeMs;

/**
 * @brief Packet Identifier generated when Publish request was sent to the broker;
 * it is used to match received Publish ACK to the transmitted Publish packet.
 */
static uint16_t usPublishPacketIdentifier;

/**
 * @brief Packet Identifier generated when Subscribe request was sent to the broker;
 * it is used to match received Subscribe ACK to the transmitted Subscribe packet.
 */
static uint16_t usSubscribePacketIdentifier;

/**
 * @brief Packet Identifier generated when Unsubscribe request was sent to the broker;
 * it is used to match received Unsubscribe response to the transmitted Unsubscribe
 * request.
 */
static uint16_t usUnsubscribePacketIdentifier;

/**
 * @brief MQTT packet type received from the MQTT broker.
 *
 * @note Only on receiving incoming PUBLISH, SUBACK, and UNSUBACK, this
 * variable is updated. For MQTT packets PUBACK and PINGRESP, the variable is
 * not updated since there is no need to specifically wait for it in this demo.
 * A single variable suffices as this demo uses single task and requests one operation
 * (of PUBLISH, SUBSCRIBE, UNSUBSCRIBE) at a time before expecting response from
 * the broker. Hence it is not possible to receive multiple packets of type PUBLISH,
 * SUBACK, and UNSUBACK in a single call of #prvWaitForPacket.
 * For a multi task application, consider a different method to wait for the packet, if needed.
 */
static uint16_t usPacketTypeReceived = 0U;

/**
 * @brief Length of the payload stored in #pucPayloadBuffer. This is set by the
 * MQTT publish callback when it copies a received payload into #pucPayloadBuffer.
 */
static size_t xPayloadLength;

/**
 * @brief Callback registered when calling xEstablishMqttSession to get incoming
 * publish messages.
 */
static MQTTPublishCallback_t xAppPublishCallback = NULL;

/**
 * @brief xSession of the PKCS #11 session
 */
CK_SESSION_HANDLE xSession = 0;

/**
 * @brief Buffer for holding received certificate until it is saved.
 */
char pcCsr[ fpdemoCSR_BUFFER_LENGTH ] = { 0 };
size_t xCsrLength = 0;
char pcCertificate[ fpdemoCERT_BUFFER_LENGTH ];
size_t xCertificateLength;
char pcCertificateId[ fpdemoCERT_ID_BUFFER_LENGTH ];
size_t xCertificateIdLength;

/**
 * @brief Buffer for holding the certificate ownership token.
 */
char pcOwnershipToken[ fpdemoOWNERSHIP_TOKEN_BUFFER_LENGTH ];
size_t xOwnershipTokenLength;

/** @brief Static buffer used to hold MQTT messages being sent and received. */
static MQTTFixedBuffer_t xBuffer =
{
    ucSharedBuffer,
    democonfigNETWORK_BUFFER_SIZE
};

struct NetworkContext
{
    SecureSocketsTransportParams_t * pParams;
};

/*-----------------------------------------------------------*/

/** \brief Provisions a private key using PKCS #11 library.
 *
 * \param[in] xSession             An initialized session handle.
 * \param[in] pucPrivateKey        Pointer to private key.  Key may either be PEM formatted
 *                                 or ASN.1 DER encoded.
 * \param[in] xPrivateKeyLength    Length of the data at pucPrivateKey, in bytes.
 * \param[in] pucLabel             PKCS #11 CKA_LABEL attribute value to be used for key.
 *                                 This should be a string values. See core_pkcs11_config.h
 * \param[out] pxObjectHandle      Points to the location that receives the PKCS #11
 *                                 private key handle created.
 *
 * \return CKR_OK upon successful key creation.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV vfpAlternateKeyProvisioning( ProvisioningParams_t * xParams );

/** \brief Provisions device with default credentials.
 *
 * Imports the certificate and private key located in
 * aws_clientcredential_keys.h to device NVM.
 *
 * \return CKR_OK upon successful credential setup.
 * Otherwise, a positive PKCS #11 error code.
 */
CK_RV vfpDevModeKeyProvisioning( void );

/**
 * @brief Calculate and perform an exponential backoff with jitter delay for
 * the next retry attempt of a failed network operation with the server.
 *
 * The function generates a random number, calculates the next backoff period
 * with the generated random number, and performs the backoff delay operation if the
 * number of retries have not exhausted.
 *
 * @note The PKCS11 module is used to generate the random number as it allows access
 * to a True Random Number Generator (TRNG) if the vendor platform supports it.
 * It is recommended to seed the random number generator with a device-specific entropy
 * source so that probability of collisions from devices in connection retries is mitigated.
 *
 * @note The backoff period is calculated using the backoffAlgorithm library.
 *
 * @param[in, out] pxRetryAttempts The context to use for backoff period calculation
 * with the backoffAlgorithm library.
 *
 * @return pdPASS if calculating the backoff period was successful; otherwise pdFAIL
 * if there was failure in random number generation OR all retry attempts had exhausted.
 */
static BaseType_t prvBackoffForRetry( BackoffAlgorithmContext_t * pxRetryParams );

/**
 * @brief Connect to MQTT broker with reconnection retries.
 *
 * If connection fails, retry is attempted after a timeout.
 * Timeout value will exponentially increase until maximum
 * timeout value is reached or the number of attempts are exhausted.
 *
 * @param[out] pxNetworkContext The output parameter to return the created network context.
 *
 * @return pdFAIL on failure; pdPASS on successful TLS+TCP network connection.
 */
static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext );

/**
 * @brief Sends an MQTT Connect packet over the already connected TLS over TCP connection.
 *
 * @param[in, out] pxMQTTContext MQTT context pointer.
 * @param[in] xNetworkContext Network context.
 *
 * @return pdFAIL on failure; pdPASS on successful MQTT connection.
 */
static BaseType_t prvCreateMQTTConnectionWithBroker( MQTTContext_t * pxMQTTContext,
                                                     NetworkContext_t * pxNetworkContext );

/**
 * @brief Subscribes to the topic as specified in mqttexampleTOPIC at the top of
 * this file. In the case of a Subscribe ACK failure, then subscription is
 * retried using an exponential backoff strategy with jitter.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 *
 * @return pdFAIL on failure; pdPASS on successful SUBSCRIBE request.
 */
static BaseType_t prvMQTTSubscribeWithBackoffRetries( MQTTContext_t * pxMQTTContext,  const char  *pcTopicFilter,
                                        uint16_t  usTopicFilterLengthconst );

/**
 * @brief Publishes a message mqttexampleMESSAGE on mqttexampleTOPIC topic.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 *
 * @return pdFAIL on failure; pdPASS on successful PUBLISH operation.
 */
static BaseType_t prvMQTTPublishToTopic( MQTTContext_t * pxMQTTContext , const char * pcTopicFilter,
                                        uint16_t usTopicFilterLengthconst, char * pcPayload, size_t xPayloadLength );

/**
 * @brief Unsubscribes from the previously subscribed topic as specified
 * in mqttexampleTOPIC.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 *
 * @return pdFAIL on failure; pdPASS on successful UNSUBSCRIBE request.
 */
static BaseType_t prvMQTTUnsubscribeFromTopic( MQTTContext_t * pxMQTTContext , const char * pcTopicFilter,
                                        uint16_t  usTopicFilterLengthconst );

/**
 * @brief The timer query function provided to the MQTT context.
 *
 * @return Time in milliseconds.
 */
static uint32_t prvGetTimeMs( void );

/**
 * @brief Process a response or ack to an MQTT request (PING, PUBLISH,
 * SUBSCRIBE or UNSUBSCRIBE). This function processes PINGRESP, PUBACK,
 * SUBACK, and UNSUBACK.
 *
 * @param[in] pxIncomingPacket is a pointer to structure containing deserialized
 * MQTT response.
 * @param[in] usPacketId is the packet identifier from the ack received.
 */
static void prvMQTTProcessResponse( MQTTPacketInfo_t * pxIncomingPacket,
                                    uint16_t usPacketId );


/**
 * @brief The application callback function for getting the incoming publishes,
 * incoming acks, and ping responses reported from the MQTT library.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 * @param[in] pxPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] pxDeserializedInfo Deserialized information from the incoming packet.
 */
static void prvEventCallback( MQTTContext_t * pxMQTTContext,
                              MQTTPacketInfo_t * pxPacketInfo,
                              MQTTDeserializedInfo_t * pxDeserializedInfo );

/**
 * @brief Helper function to wait for a specific incoming packet from the
 * broker.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 * @param[in] usPacketType Packet type to wait for.
 *
 * @return The return status from call to #MQTT_ProcessLoop API.
 */
static MQTTStatus_t prvWaitForPacket( MQTTContext_t * pxMQTTContext,
                                      uint16_t usPacketType );
/**
 * @brief Callback to receive the incoming publish messages from the MQTT
 * broker. Sets xResponseStatus if an expected CreateCertificateFromCsr or
 * RegisterThing response is received, and copies the response into
 * responseBuffer if the response is an accepted one.
 *
 * @param[in] pPublishInfo Pointer to publish info of the incoming publish.
 * @param[in] usPacketIdentifier Packet identifier of Packet size sent incoming publish.
 */

static void prvProvisioningPublishCallback( MQTTPublishInfo_t * pPublishInfo,
                                            uint16_t usPacketIdentifier );


/*-----------------------------------------------------------*/

/*
 * @brief The example shown below uses MQTT APIs to create MQTT messages and
 * send them over the mutually authenticated network connection established with the
 * MQTT broker, utilising Pkcs11 authentication and cbor encoder.
 * This example is single threaded and uses statically allocated
 * memory. It uses QoS1 for sending to and receiving messages from the broker.
 *
 * This MQTT client subscribes to the topic as specified in required fleet provisioning topics
 * by sending a subscribe packet and then waiting for a subscribe
 * acknowledgment (SUBACK).
 *
 * This example runs for democonfigMQTT_MAX_DEMO_COUNT, if the
 * connection to the broker goes down, the code tries to reconnect to the broker
 * with an exponential backoff mechanism.
 */
int RunFleetProvisioningDemo( bool awsIotMqttMode,
                               const char * pIdentifier,
                               void * pNetworkServerInfo,
                               void * pNetworkCredentialInfo,
                               const IotNetworkInterface_t * pNetworkInterface )
{
    NetworkContext_t xNetworkContext = { 0 };
    MQTTContext_t xMQTTContext = { 0 };
    MQTTStatus_t xMQTTStatus;
    TransportSocketStatus_t xNetworkStatus;
    BaseType_t xIsConnectionEstablished = pdFALSE;
    SecureSocketsTransportParams_t secureSocketsTransportParams = { 0 };

    CK_RV xResult = CKR_OK;

    /* Initialize the buffer lengths to their max lengths. */
    xCertificateLength = fpdemoCERT_BUFFER_LENGTH;
    xCertificateIdLength = fpdemoCERT_ID_BUFFER_LENGTH;
    xOwnershipTokenLength = fpdemoOWNERSHIP_TOKEN_BUFFER_LENGTH;

    /* Upon return, pdPASS will indicate a successful demo execution.
    * pdFAIL will indicate some failures occurred during execution. The
    * user of this demo must check the logs for any failure codes. */
    BaseType_t xDemoStatus = pdFAIL;

    /* Remove compiler warnings about unused parameters. */
    ( void ) awsIotMqttMode;
    ( void ) pIdentifier;
    ( void ) pNetworkServerInfo;
    ( void ) pNetworkCredentialInfo;
    ( void ) pNetworkInterface;

    /* Set the entry time of the demo application. This entry time will be used
     * to calculate relative time elapsed in the execution of the demo application,
     * by the timer utility function that is provided to the MQTT library.
     */

    ulGlobalEntryTimeMs = prvGetTimeMs();
    xNetworkContext.pParams = &secureSocketsTransportParams;

    /* Open Pkcs11 Session to parse claim cert & generate Key and CSR */
    xResult = vfpDevModeKeyProvisioning();
    if ( xResult != CKR_OK)
    {
        xDemoStatus = pdFAIL;
    }
    /****************************** Connect. ******************************/

    /* Attempt to establish TLS session with MQTT broker. If connection fails,
     * retry after a timeout. Timeout value will be exponentially increased until
     * the maximum number of attempts are reached or the maximum timeout value is reached.
     * The function returns a failure status if the TLS over TCP connection cannot be established
     * to the broker after the configured number of attempts. */
    xDemoStatus = prvConnectToServerWithBackoffRetries( &xNetworkContext );

    if( xDemoStatus == pdPASS )
    {
        /* Set a flag indicating a TLS connection exists. This is done to
         * disconnect if the loop exits before disconnection happens. */
        xIsConnectionEstablished = pdTRUE;

        /* Sends an MQTT Connect packet over the already established TLS connection,
         * and waits for connection acknowledgment (CONNACK) packet. */
        LogInfo( ( "Creating an MQTT connection to %s.\n", democonfigMQTT_BROKER_ENDPOINT ) );
        xDemoStatus = prvCreateMQTTConnectionWithBroker( &xMQTTContext, &xNetworkContext );

    }

    /**************************** Subscribe Fleet provisioning CSR Topics ******************************/

    if( xDemoStatus == pdPASS )
    {
        /* If server rejected the subscription request, attempt to resubscribe to topic.
         * Attempts are made according to the exponential backoff retry strategy
         * implemented in backoff_algorithm. */
        LogInfo( ( "Subscribe to fleet provisioning CSR Topics\n" ) );
        xDemoStatus = prvMQTTSubscribeWithBackoffRetries( &xMQTTContext, FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC,
                             FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH );

        xDemoStatus = prvMQTTSubscribeWithBackoffRetries( &xMQTTContext, FP_CBOR_CREATE_CERT_REJECTED_TOPIC,
                             FP_CBOR_CREATE_CERT_REJECTED_LENGTH );

    }

    /**Create the request CSR payload to CreateCertificateFromCsr APIs */
    if (xGenerateCsrRequest( pucPayloadBuffer,
                           democonfigNETWORK_BUFFER_SIZE,
                           pcCsr,
                           xCsrLength,
                           &xPayloadLength ) != true)
    {
        xDemoStatus = pdFAIL;
    }

    /**************************** Publish and Keep Alive Loop. ******************************/

    LogInfo( ( "Publish to the MQTT topic %s.\n", FP_CBOR_CREATE_CERT_PUBLISH_TOPIC ) );
    xDemoStatus = prvMQTTPublishToTopic( &xMQTTContext, FP_CBOR_CREATE_CERT_PUBLISH_TOPIC,
                                FP_CBOR_CREATE_CERT_PUBLISH_LENGTH, ( char * ) pucPayloadBuffer, xPayloadLength);


    if( xDemoStatus == pdPASS )
    {
        /* Process incoming publish, since application subscribed to the same
         * topic, the broker will send publish message back to the application.
         * #prvWaitForPacket will try to receive an incoming PUBLISH packet from broker.
         * Please note that PUBACK for the outgoing PUBLISH may also be received before
         * receiving an incoming PUBLISH. */
        LogInfo( ( "Attempt to receive publish message from broker.\n" ) );
        xMQTTStatus = prvWaitForPacket( &xMQTTContext, MQTT_PACKET_TYPE_PUBLISH );
    }

    if( xDemoStatus == pdPASS )
    {

        /* From the response, extract the certificate, certificate ID, and
         * certificate ownership token. */
        if( xParseCsrResponse( pucPayloadBuffer,
                         xPayloadLength,
                         pcCertificate,
                         &xCertificateLength,
                         pcCertificateId,
                         &xCertificateIdLength,
                         pcOwnershipToken,
                         &xOwnershipTokenLength ) != true )

        {
            xDemoStatus = pdFAIL;

        } else {
            LogInfo( ( "Received certificate with Id: %.*s\n", ( int ) xCertificateIdLength, pcCertificateId ) );
        }
    }

    /* Save the certificate into PKCS #11. */
    if( xLoadCertificate( xSession,
                    pcCertificate,
                    pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                    xCertificateLength ) != true  )
    {
        xDemoStatus = pdFAIL;
    }

    /************************ Unsubscribe from the Claim topic. **************************/

    if( xDemoStatus == pdPASS )
    {

            LogInfo( ( "Unsubscribe fleet provisioning CSR Topics\n" ) );

        xDemoStatus = prvMQTTUnsubscribeFromTopic( &xMQTTContext, FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC,
                 FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH );
        xDemoStatus = prvMQTTUnsubscribeFromTopic( &xMQTTContext, FP_CBOR_CREATE_CERT_REJECTED_TOPIC,
                 FP_CBOR_CREATE_CERT_REJECTED_LENGTH );
    }

    /************************ Generate Register Thing Request. **************************/
    if( xDemoStatus == pdPASS )
    {
        if (xGenerateRegisterThingRequest( pucPayloadBuffer,
                                     democonfigNETWORK_BUFFER_SIZE,
                                     pcOwnershipToken,
                                     xOwnershipTokenLength,
                                     democonfigFP_DEMO_ID,
                                     fpdemoFP_DEMO_ID_LENGTH,
                                     &xPayloadLength ) != true)
        {
            xDemoStatus = pdFAIL;
        }
    }

    /************************ Subscribe to RegisterThing reply topics. **************************/
        if( xDemoStatus == pdPASS )
    {
        LogInfo( ( "Subscribe to registerThing reply topics" ) );
        xDemoStatus = prvMQTTSubscribeWithBackoffRetries( &xMQTTContext, FP_CBOR_REGISTER_ACCEPTED_TOPIC( democonfigPROVISIONING_TEMPLATE_NAME ),
                                         FP_CBOR_REGISTER_ACCEPTED_LENGTH( fpdemoPROVISIONING_TEMPLATE_NAME_LENGTH ) );
        xDemoStatus = prvMQTTSubscribeWithBackoffRetries( &xMQTTContext, FP_CBOR_REGISTER_REJECTED_TOPIC( democonfigPROVISIONING_TEMPLATE_NAME ),
                                 FP_CBOR_REGISTER_REJECTED_LENGTH( fpdemoPROVISIONING_TEMPLATE_NAME_LENGTH ) );
     }

    /* Publish the RegisterThing request. */
        if( xDemoStatus == pdPASS )
    {

        LogInfo( ( "Publish to the MQTT topic %s.\n", FP_CBOR_REGISTER_PUBLISH_TOPIC( democonfigPROVISIONING_TEMPLATE_NAME ) ) );
        xDemoStatus = prvMQTTPublishToTopic( &xMQTTContext, FP_CBOR_REGISTER_PUBLISH_TOPIC( democonfigPROVISIONING_TEMPLATE_NAME ),
                         FP_CBOR_REGISTER_PUBLISH_LENGTH( fpdemoPROVISIONING_TEMPLATE_NAME_LENGTH ),
                         ( char * ) pucPayloadBuffer,
                         xPayloadLength );

        if( xDemoStatus == pdFAIL )
        {

            LogError( ( "Failed to publish to fleet provisioning topic: %.*s.\n",
                        FP_CBOR_REGISTER_PUBLISH_LENGTH( fpdemoPROVISIONING_TEMPLATE_NAME_LENGTH ),
                        FP_CBOR_REGISTER_PUBLISH_TOPIC( democonfigPROVISIONING_TEMPLATE_NAME ) ) );
        }
    }

    /* Wait for Publish Ack */
    if( xDemoStatus == pdPASS )
    {
        /* Process incoming publish, since application subscribed to the same
         * topic, the broker will send publish message back to the application.
         * #prvWaitForPacket will try to receive an incoming PUBLISH packet from broker.
         * Please note that PUBACK for the outgoing PUBLISH may also be received before
         * receiving an incoming PUBLISH. */
        LogInfo( ( "Attempt to receive publish message from broker.\n" ) );
        xMQTTStatus = prvWaitForPacket( &xMQTTContext, MQTT_PACKET_TYPE_PUBLISH );

        if( xMQTTStatus != MQTTSuccess )
        {
            xDemoStatus = pdFAIL;
        }
    }

    if( xDemoStatus == pdPASS )
    {
        /* Extract the Thing name from the response. */
        xThingNameLength = fpdemoMAX_THING_NAME_LENGTH;
        if ( xParseRegisterThingResponse( pucPayloadBuffer,
                                   xPayloadLength,
                                   pcThingName,
                                   &xThingNameLength ) != true )
        {
            xDemoStatus = pdFAIL;
       }

        if( xDemoStatus == pdPASS )
        {
            LogInfo( ( "Received AWS IoT Thing name: %.*s\n", ( int ) xThingNameLength, pcThingName ) );

        }
    }

    /* Unsubscribe from RegisterThing Topics */
    if( xDemoStatus == pdPASS )
    {
        xDemoStatus = prvMQTTUnsubscribeFromTopic( &xMQTTContext, FP_CBOR_REGISTER_ACCEPTED_TOPIC( democonfigPROVISIONING_TEMPLATE_NAME ),
                                        FP_CBOR_REGISTER_ACCEPTED_LENGTH( fpdemoPROVISIONING_TEMPLATE_NAME_LENGTH ) );
        xDemoStatus = prvMQTTUnsubscribeFromTopic( &xMQTTContext, FP_CBOR_REGISTER_REJECTED_TOPIC( democonfigPROVISIONING_TEMPLATE_NAME ),
                                         FP_CBOR_REGISTER_REJECTED_LENGTH( fpdemoPROVISIONING_TEMPLATE_NAME_LENGTH ) );

    }

    /**************************** Disconnect. ******************************/

    if( xDemoStatus == pdPASS )
    {
        /* Send an MQTT Disconnect packet over the already connected TLS over TCP connection.
         * There is no corresponding response for the disconnect packet. After sending
         * disconnect, client must close the network connection. */
        LogInfo( ( "Disconnecting the MQTT connection with %s.\n", democonfigMQTT_BROKER_ENDPOINT ) );
        xMQTTStatus = MQTT_Disconnect( &xMQTTContext );
    }

    /* We will always close the network connection, even if an error may have occurred during
     * demo execution, to clean up the system resources that it may have consumed. */
    if( xIsConnectionEstablished == pdTRUE )
    {
        /* Close the network connection.  */
        xNetworkStatus = SecureSocketsTransport_Disconnect( &xNetworkContext );

        if( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS )
        {
            xDemoStatus = pdFAIL;
            LogError( ( "SecureSocketsTransport_Disconnect() failed to close the network connection. "
                        "StatusCode=%d.\n", ( int ) xNetworkStatus ) );
        }

        /* Reset the connection flag back to false */
            xIsConnectionEstablished = pdFALSE;
    }
    return ( xDemoStatus == pdPASS ) ? EXIT_SUCCESS : EXIT_FAILURE;
}
/*-----------------------------------------------------------*/

/* Perform device provisioning using the specified TLS client credentials
 * specifically done for fleet provisioning key & CSR creation.
 */
CK_RV vfpAlternateKeyProvisioning( ProvisioningParams_t * xParams )
{
    CK_RV xResult = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    bool res;

    xResult = C_GetFunctionList( &pxFunctionList );

    /* Initialize the PKCS Module */
    if( xResult == CKR_OK )
    {
        xResult = xInitializePkcs11Token();
    }

    if( xResult == CKR_OK )
    {
        xResult = xInitializePkcs11Session( &xSession );
    }

    if( xResult == CKR_OK )
    {
        /* Generate Key & Csr inside pkcs11 session */
        res = xGenerateKeyAndCsr( xSession,
                              pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                              pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                              pcCsr,
                              fpdemoCSR_BUFFER_LENGTH,
                              &xCsrLength );
    }
    if( res != true )
    {
        LogError( ( "Failed to generate Key and Certificate Signing Request." ) );
    }

    if( xResult == CKR_OK )
    {
        /* Provision device using Claim Certificate */
        xResult = xProvisionDevice( xSession, xParams );
    }

    pxFunctionList->C_CloseSession( xSession );

    return xResult;
}

/* Perform device provisioning using the default TLS client credentials
 * specially done for fleet provisioning due to CSR cert used in this example.
 */
CK_RV vfpDevModeKeyProvisioning( void )
{
    ProvisioningParams_t xParams;

    xParams.pucJITPCertificate = ( uint8_t * ) keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM;
    xParams.pucClientPrivateKey = ( uint8_t * ) keyCLIENT_PRIVATE_KEY_PEM;
    xParams.pucClientCertificate = ( uint8_t * ) keyCLIENT_CERTIFICATE_PEM;

    /* If using a JITR flow, a JITR certificate must be supplied. If using credentials generated by
     * AWS, this certificate is not needed. */
    if( ( NULL != xParams.pucJITPCertificate ) &&
        ( 0 != strcmp( "", ( const char * ) xParams.pucJITPCertificate ) ) )
    {
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulJITPCertificateLength = sizeof( char ) + strlen( ( const char * ) xParams.pucJITPCertificate );
    }
    else
    {
        xParams.pucJITPCertificate = NULL;
    }

    /* The hard-coded client certificate and private key can be useful for
     * first-time lab testing. They are optional after the first run, though, and
     * not recommended at all for going into production. */
    if( ( NULL != xParams.pucClientPrivateKey ) &&
        ( 0 != strcmp( "", ( const char * ) xParams.pucClientPrivateKey ) ) )
    {
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulClientPrivateKeyLength = sizeof( char ) + strlen( ( const char * ) xParams.pucClientPrivateKey );
    }
    else
    {
        xParams.pucClientPrivateKey = NULL;
    }

    if( ( NULL != xParams.pucClientCertificate ) &&
        ( 0 != strcmp( "", ( const char * ) xParams.pucClientCertificate ) ) )
    {
        /* We want the NULL terminator to be written to storage, so include it
         * in the length calculation. */
        xParams.ulClientCertificateLength = sizeof( char ) + strlen( ( const char * ) xParams.pucClientCertificate );
    }
    else
    {
        xParams.pucClientCertificate = NULL;
    }

    return vfpAlternateKeyProvisioning( &xParams );
}

static BaseType_t prvBackoffForRetry( BackoffAlgorithmContext_t * pxRetryParams )
{
    BaseType_t xReturnStatus = pdFAIL;
    uint16_t usNextRetryBackOff = 0U;
    BackoffAlgorithmStatus_t xBackoffAlgStatus = BackoffAlgorithmSuccess;

    /**
     * To calculate the backoff period for the next retry attempt, we will
     * generate a random number to provide to the backoffAlgorithm library.
     *
     * Note: The PKCS11 module is used to generate the random number as it allows access
     * to a True Random Number Generator (TRNG) if the vendor platform supports it.
     * It is recommended to use a random number generator seeded with a device-specific
     * entropy source so that probability of collisions from devices in connection retries
     * is mitigated.
     */
    uint32_t ulRandomNum = 0;

    if( xPkcs11GenerateRandomNumber( ( uint8_t * ) &ulRandomNum,
                                     sizeof( ulRandomNum ) ) == pdPASS )
    {
        /* Get back-off value (in milliseconds) for the next retry attempt. */
        xBackoffAlgStatus = BackoffAlgorithm_GetNextBackoff( pxRetryParams, ulRandomNum, &usNextRetryBackOff );

        if( xBackoffAlgStatus == BackoffAlgorithmRetriesExhausted )
        {
            LogError( ( "All retry attempts have exhausted. Operation will not be retried" ) );
        }
        else if( xBackoffAlgStatus == BackoffAlgorithmSuccess )
        {
            /* Perform the backoff delay. */
            vTaskDelay( pdMS_TO_TICKS( usNextRetryBackOff ) );

            xReturnStatus = pdPASS;

            LogInfo( ( "Retry attempt %lu out of maximum retry attempts %lu.",
                       ( pxRetryParams->attemptsDone + 1 ),
                       pxRetryParams->maxRetryAttempts ) );
        }
    }
    else
    {
        LogError( ( "Unable to retry operation with broker: Random number generation failed" ) );
    }

    return xReturnStatus;
}

/*-----------------------------------------------------------*/

static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pxNetworkContext )
{
    ServerInfo_t xServerInfo = { 0 };

    SocketsConfig_t xSocketsConfig = { 0 };
    BaseType_t xStatus = pdPASS;
    TransportSocketStatus_t xNetworkStatus = TRANSPORT_SOCKET_STATUS_SUCCESS;
    BackoffAlgorithmContext_t xReconnectParams;
    BaseType_t xBackoffStatus = pdFALSE;

    /* Set the credentials for establishing a TLS connection. */
    /* Initializer server information. */
    xServerInfo.pHostName = democonfigMQTT_BROKER_ENDPOINT;
    xServerInfo.hostNameLength = strlen( democonfigMQTT_BROKER_ENDPOINT );
    xServerInfo.port = democonfigMQTT_BROKER_PORT;

    /* Configure credentials for TLS mutual authenticated session. */
    xSocketsConfig.enableTls = true;
    xSocketsConfig.pAlpnProtos = NULL;
    xSocketsConfig.maxFragmentLength = 0;
    xSocketsConfig.disableSni = false;
    xSocketsConfig.pRootCa = democonfigROOT_CA_PEM;
    xSocketsConfig.rootCaSize = sizeof( democonfigROOT_CA_PEM );
    xSocketsConfig.sendTimeoutMs = mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;
    xSocketsConfig.recvTimeoutMs = mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS;

    /* Initialize reconnect attempts and interval. */
    BackoffAlgorithm_InitializeParams( &xReconnectParams,
                                       RETRY_BACKOFF_BASE_MS,
                                       RETRY_MAX_BACKOFF_DELAY_MS,
                                       RETRY_MAX_ATTEMPTS );

    /* Attempt to connect to MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will exponentially increase till maximum
     * attempts are reached.
     */
    do
    {
        /* Establish a TLS session with the MQTT broker. This example connects to
         * the MQTT broker as specified in democonfigMQTT_BROKER_ENDPOINT and
         * democonfigMQTT_BROKER_PORT at the top of this file. */
        LogInfo( ( "Creating a TLS connection to %s:%u.",
                   democonfigMQTT_BROKER_ENDPOINT,
                   democonfigMQTT_BROKER_PORT ) );
        /* Attempt to create a mutually authenticated TLS connection. */

        xNetworkStatus = SecureSocketsTransport_Connect( pxNetworkContext,
                                                         &xServerInfo,
                                                         &xSocketsConfig );

        if( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS )
        {
            LogWarn( ( "Connection to the broker failed. Attempting connection retry after backoff delay." ) );

            /* As the connection attempt failed, we will retry the connection after an
             * exponential backoff with jitter delay. */

            /* Calculate the backoff period for the next retry attempt and perform the wait operation. */
            xBackoffStatus = prvBackoffForRetry( &xReconnectParams );
        }
    } while( ( xNetworkStatus != TRANSPORT_SOCKET_STATUS_SUCCESS ) && ( xBackoffStatus == pdPASS ) );

    return xStatus;
}
/*-----------------------------------------------------------*/

static BaseType_t prvCreateMQTTConnectionWithBroker( MQTTContext_t * pxMQTTContext,
                                                     NetworkContext_t * pxNetworkContext )
{
    MQTTStatus_t xResult;
    MQTTConnectInfo_t xConnectInfo;
    bool xSessionPresent;
    TransportInterface_t xTransport;
    BaseType_t xStatus = pdFAIL;

    /* Fill in Transport Interface send and receive function pointers. */
    xTransport.pNetworkContext = pxNetworkContext;
    xTransport.send = SecureSocketsTransport_Send;
    xTransport.recv = SecureSocketsTransport_Recv;

    /* Initialize MQTT library. */
    xResult = MQTT_Init( pxMQTTContext, &xTransport, prvGetTimeMs, prvEventCallback, &xBuffer );
    configASSERT( xResult == MQTTSuccess );

    /* Some fields are not used in this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xConnectInfo, 0x00, sizeof( xConnectInfo ) );

    /* Start with a clean session i.e. direct the MQTT broker to discard any
     * previous session data. Also, establishing a connection with clean session
     * will ensure that the broker does not store any data when this client
     * gets disconnected. */
    xConnectInfo.cleanSession = true;

    /* The client identifier is used to uniquely identify this MQTT client to
     * the MQTT broker. In a production device the identifier can be something
     * unique, such as a device serial number. */
    xConnectInfo.pClientIdentifier = democonfigCLIENT_IDENTIFIER;
    xConnectInfo.clientIdentifierLength = ( uint16_t ) strlen( democonfigCLIENT_IDENTIFIER );

    /* Set MQTT keep-alive period. If the application does not send packets at an interval less than
     * the keep-alive period, the MQTT library will send PINGREQ packets. */
    xConnectInfo.keepAliveSeconds = mqttexampleKEEP_ALIVE_TIMEOUT_SECONDS;

    /* Remember the publish callback supplied. */
    xAppPublishCallback = prvProvisioningPublishCallback;

    /* Send MQTT CONNECT packet to broker. LWT is not used in this demo, so it
     * is passed as NULL. */
    xResult = MQTT_Connect( pxMQTTContext,
                            &xConnectInfo,
                            NULL,
                            CONNACK_RECV_TIMEOUT_MS,
                            &xSessionPresent );

    if( xResult != MQTTSuccess )
    {
        LogError( ( "Failed to establish MQTT connection: Server=%s, MQTTStatus=%s",
                    democonfigMQTT_BROKER_ENDPOINT, MQTT_Status_strerror( xResult ) ) );
    }
    else
    {
        /* Successfully established and MQTT connection with the broker. */
        LogInfo( ( "An MQTT connection is established with %s.", democonfigMQTT_BROKER_ENDPOINT ) );
        xStatus = pdPASS;
    }

    return xStatus;
}

/*-----------------------------------------------------------*/

static BaseType_t prvMQTTSubscribeWithBackoffRetries( MQTTContext_t * pxMQTTContext , const char  *pcTopicFilter,
                                        uint16_t   usTopicFilterLengthconst )
{
    MQTTStatus_t xResult = MQTTSuccess;
    BackoffAlgorithmContext_t xRetryParams;
    MQTTSubscribeInfo_t xMQTTSubscription[ mqttexampleTOPIC_COUNT ];
    BaseType_t xStatus = pdFAIL;

    /* Some fields not used by this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xMQTTSubscription, 0x00, sizeof( xMQTTSubscription ) );

    /* Get a unique packet id. */
    usSubscribePacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Subscribe to the mqttexampleTOPIC topic filter. This example subscribes to
     * only one topic and uses QoS1. */

    xMQTTSubscription[ 0 ].qos = MQTTQoS1;
    xMQTTSubscription[ 0 ].pTopicFilter = pcTopicFilter;
    xMQTTSubscription[ 0 ].topicFilterLength = usTopicFilterLengthconst;

    /* Initialize retry attempts and interval. */
    BackoffAlgorithm_InitializeParams( &xRetryParams,
                                       RETRY_BACKOFF_BASE_MS,
                                       RETRY_MAX_BACKOFF_DELAY_MS,
                                       RETRY_MAX_ATTEMPTS );

    xResult = MQTT_Subscribe( pxMQTTContext,
                              xMQTTSubscription,
                              sizeof( xMQTTSubscription ) / sizeof( MQTTSubscribeInfo_t ),
                              usSubscribePacketIdentifier );

    if( xResult != MQTTSuccess )
    {
            LogError( ( "Failed to SUBSCRIBE to MQTT topic %s. Error=%s\n",
                        pcTopicFilter , MQTT_Status_strerror( xResult ) ) );
    }
    else
    {
        /* Process incoming packet from the broker. Acknowledgment for subscription
         * ( SUBACK ) will be received here. However after sending the subscribe, the
         * client may receive a publish before it receives a subscribe ack. Since this
         * demo is subscribing to the topic to which no one is publishing, probability
         * of receiving publish message before subscribe ack is zero; but application
         * must be ready to receive any packet. This demo uses MQTT_ProcessLoop to
         * receive packet from network. */

        xResult = MQTT_ProcessLoop( pxMQTTContext, CONNACK_RECV_TIMEOUT_MS );

        if ( xResult != MQTTSuccess )
        {
            LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                        MQTT_Status_strerror( xResult ) ) );
        }
        else
        {
            xStatus = pdPASS;
        }
    }

    return xStatus;
}
/*-----------------------------------------------------------*/


static BaseType_t prvMQTTPublishToTopic( MQTTContext_t * pxMQTTContext , const char * pcTopicFilter,
                                        uint16_t usTopicFilterLengthconst, char * pcPayload, size_t xPayloadLength )
{
    MQTTStatus_t xResult;
    MQTTPublishInfo_t xMQTTPublishInfo;
    BaseType_t xStatus = pdPASS;

    /* Some fields are not used by this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xMQTTPublishInfo, 0x00, sizeof( xMQTTPublishInfo ) );

    /* This demo uses QoS1. */
    xMQTTPublishInfo.qos = MQTTQoS1;
    xMQTTPublishInfo.retain = false;
    xMQTTPublishInfo.pTopicName = pcTopicFilter;
    xMQTTPublishInfo.topicNameLength = usTopicFilterLengthconst;
    xMQTTPublishInfo.pPayload = pcPayload;
    xMQTTPublishInfo.payloadLength = xPayloadLength;

    /* Get a unique packet id. */
    usPublishPacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Send PUBLISH packet. Packet ID is not used for a QoS1 publish. */
    xResult = MQTT_Publish( pxMQTTContext, &xMQTTPublishInfo, usPublishPacketIdentifier );

    if( xResult != MQTTSuccess )
    {
        xStatus = pdFAIL;
        LogError( ( "Failed to send PUBLISH message to broker: Topic=%s, Error=%s",
                    pcTopicFilter,
                    MQTT_Status_strerror( xResult ) ) );
    }
    return xStatus;
}
/*-----------------------------------------------------------*/

static BaseType_t prvMQTTUnsubscribeFromTopic( MQTTContext_t * pxMQTTContext , const char * pcTopicFilter,
                                        uint16_t  usTopicFilterLengthconst )
{
    MQTTStatus_t xResult = MQTTSuccess;
    MQTTSubscribeInfo_t xMQTTSubscription[ mqttexampleTOPIC_COUNT ];
    BaseType_t xStatus = pdPASS;

    /* Some fields not used by this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xMQTTSubscription, 0x00, sizeof( xMQTTSubscription ) );

    /* Get a unique packet id. */
    usSubscribePacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Subscribe to the mqttexampleTOPIC topic filter. This example subscribes to
     * only one topic and uses QoS1. */

    xMQTTSubscription[ 0 ].qos = MQTTQoS1;
    xMQTTSubscription[ 0 ].pTopicFilter = pcTopicFilter ;
    xMQTTSubscription[ 0 ].topicFilterLength = usTopicFilterLengthconst ;


    /* Get next unique packet identifier. */
    usUnsubscribePacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Send UNSUBSCRIBE packet. */
    xResult = MQTT_Unsubscribe( pxMQTTContext,
                                xMQTTSubscription,
                                sizeof( xMQTTSubscription ) / sizeof( MQTTSubscribeInfo_t ),
                                usUnsubscribePacketIdentifier );

    if( xResult != MQTTSuccess )
    {
        LogError( ( "Failed to send UNSUBSCRIBE packet to broker with error = %s.",
                   MQTT_Status_strerror( xResult ) ) );
    }
    else
    {
        LogDebug( ( "UNSUBSCRIBE sent topic %.*s to broker.",
                   usTopicFilterLengthconst,
                   pcTopicFilter ) );

        /* Process incoming packet from the broker. Acknowledgment for unsubscribe
        * operation ( UNSUBACK ) will be received here. This demo uses
        * MQTT_ProcessLoop to receive packet from network. */
        xResult = MQTT_ProcessLoop( pxMQTTContext, CONNACK_RECV_TIMEOUT_MS );

        if( xResult != MQTTSuccess )
        {
            LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                        MQTT_Status_strerror( xResult ) ) );
            xStatus = pdFAIL;
        }
        else
        {
            xStatus = pdPASS;
        }
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

static void prvMQTTProcessResponse( MQTTPacketInfo_t * pxIncomingPacket,
                                    uint16_t usPacketId )
{
    switch( pxIncomingPacket->type )
    {
        case MQTT_PACKET_TYPE_PUBACK:
//            LogInfo( ( "PUBACK received for packet Id %u.\n", usPacketId ) );
            /* Make sure ACK packet identifier matches with Request packet identifier. */
            configASSERT( usPublishPacketIdentifier == usPacketId );
            break;

        case MQTT_PACKET_TYPE_SUBACK:
            /* Update the packet type received to SUBACK. */
            usPacketTypeReceived = MQTT_PACKET_TYPE_SUBACK;
            /* Make sure ACK packet identifier matches with Request packet identifier. */
            configASSERT( usSubscribePacketIdentifier == usPacketId );
            break;

        case MQTT_PACKET_TYPE_UNSUBACK:
            /* Update the packet type received to UNSUBACK. */
            usPacketTypeReceived = MQTT_PACKET_TYPE_UNSUBACK;

            /* Make sure ACK packet identifier matches with Request packet identifier. */
            configASSERT( usUnsubscribePacketIdentifier == usPacketId );
            break;

        case MQTT_PACKET_TYPE_PINGRESP:
            LogInfo( ( "Ping Response successfully received.\n" ) );

            break;

        /* Any other packet type is invalid. */
        default:
            LogWarn( ( "prvMQTTProcessResponse() called with unknown packet type:(%02X).\n",
                       pxIncomingPacket->type ) );
    }
}

/*-----------------------------------------------------------*/

static void prvProvisioningPublishCallback( MQTTPublishInfo_t * pPublishInfo,
                                            uint16_t usPacketIdentifier )
{
    FleetProvisioningStatus_t status;
    FleetProvisioningTopic_t api;

    usPacketTypeReceived = MQTT_PACKET_TYPE_PUBLISH;

    /* Silence compiler warnings about unused variables. */
    ( void ) usPacketIdentifier;

    status = FleetProvisioning_MatchTopic( pPublishInfo->pTopicName,
                                           pPublishInfo->topicNameLength, &api );

    if( status != FleetProvisioningSuccess )
    {
        LogWarn( ( "Unexpected publish message received. Topic: %.*s.",
                   ( int ) pPublishInfo->topicNameLength,
                   ( const char * ) pPublishInfo->pTopicName ) );
    }
    else
    {
        if( api == FleetProvCborCreateCertFromCsrAccepted )
        {
            LogInfo( ( "Received accepted response from Fleet Provisioning CreateCertificateFromCsr API." ) );

//            xResponseStatus = ResponseAccepted;

            /* Copy the payload from the MQTT library's buffer to #pucPayloadBuffer. */
            ( void ) memcpy( ( void * ) pucPayloadBuffer,
                             ( const void * ) pPublishInfo->pPayload,
                             ( size_t ) pPublishInfo->payloadLength );


            xPayloadLength = pPublishInfo->payloadLength;
        }
        else if( api == FleetProvCborCreateCertFromCsrRejected )
        {
            LogError( ( "Received rejected response from Fleet Provisioning CreateCertificateFromCsr API." ) );

//            xResponseStatus = ResponseRejected;
        }
        else if( api == FleetProvCborRegisterThingAccepted )
        {
            LogInfo( ( "Received accepted response from Fleet Provisioning RegisterThing API." ) );

//            xResponseStatus = ResponseAccepted;

            /* Copy the payload from the MQTT library's buffer to #pucPayloadBuffer. */
            ( void ) memcpy( ( void * ) pucPayloadBuffer,
                             ( const void * ) pPublishInfo->pPayload,
                             ( size_t ) pPublishInfo->payloadLength );

            xPayloadLength = pPublishInfo->payloadLength;
        }
        else if( api == FleetProvCborRegisterThingRejected )
        {
            LogError( ( "Received rejected response from Fleet Provisioning RegisterThing API." ) );

//            xResponseStatus = ResponseRejected;
        }
        else
        {
            LogError( ( "Received message on unexpected Fleet Provisioning topic. Topic: %.*s.",
                        ( int ) pPublishInfo->topicNameLength,
                        ( const char * ) pPublishInfo->pTopicName ) );
        }
    }
}
/*-----------------------------------------------------------*/

static void prvEventCallback( MQTTContext_t * pxMQTTContext,
                              MQTTPacketInfo_t * pxPacketInfo,
                              MQTTDeserializedInfo_t * pxDeserializedInfo )
{
    /* The MQTT context is not used for this demo. */
    ( void ) pxMQTTContext;


    if( ( pxPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {

         configASSERT( pxDeserializedInfo->pPublishInfo != NULL );

        /* Utilisiing Fleet provisiong Freertos callback */
        if( xAppPublishCallback != NULL )
        {
            xAppPublishCallback( pxDeserializedInfo->pPublishInfo, pxDeserializedInfo->packetIdentifier );
        }
    }
    else
    {
        prvMQTTProcessResponse( pxPacketInfo, pxDeserializedInfo->packetIdentifier );
    }
}

/*-----------------------------------------------------------*/

static uint32_t prvGetTimeMs( void )
{
    TickType_t xTickCount = 0;
    uint32_t ulTimeMs = 0UL;

    /* Get the current tick count. */
    xTickCount = xTaskGetTickCount();

    /* Convert the ticks to milliseconds. */
    ulTimeMs = ( uint32_t ) xTickCount * MILLISECONDS_PER_TICK;

    /* Reduce ulGlobalEntryTimeMs from obtained time so as to always return the
     * elapsed time in the application. */
    ulTimeMs = ( uint32_t ) ( ulTimeMs - ulGlobalEntryTimeMs );

    return ulTimeMs;
}

/*-----------------------------------------------------------*/

static MQTTStatus_t prvWaitForPacket( MQTTContext_t * pxMQTTContext,
                                      uint16_t usPacketType )
{
    uint8_t ucCount = 0U;
    MQTTStatus_t xMQTTStatus = MQTTSuccess;

    /* Reset the packet type received. */
    usPacketTypeReceived = 0U;

    while( ( usPacketTypeReceived != usPacketType ) &&
           ( ucCount++ < MQTT_PROCESS_LOOP_PACKET_WAIT_COUNT_MAX ) &&
           ( xMQTTStatus == MQTTSuccess ) )
    {
        /* Event callback will set #usPacketTypeReceived when receiving appropriate packet. This
         * will wait for at most mqttexamplePROCESS_LOOP_TIMEOUT_MS. */
        xMQTTStatus = MQTT_ProcessLoop( pxMQTTContext, mqttexamplePROCESS_LOOP_TIMEOUT_MS );
    }

    if( ( xMQTTStatus != MQTTSuccess ) || ( usPacketTypeReceived != usPacketType ) )
    {
        LogError( ( "MQTT_ProcessLoop failed to receive packet: Packet type=%02X, LoopDuration=%u, Status=%s",
                    usPacketType,
                    ( mqttexamplePROCESS_LOOP_TIMEOUT_MS * ucCount ),
                    MQTT_Status_strerror( xMQTTStatus ) ) );
    }

    return xMQTTStatus;
}

/*-----------------------------------------------------------*/
