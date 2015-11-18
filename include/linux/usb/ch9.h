/*
 * This file holds USB constants and structures that are needed for
 * USB device APIs.  These are used by the USB device model, which is
 * defined in chapter 9 of the USB 2.0 specification and in the
 * Wireless USB 1.0 (spread around).  Linux has several APIs in C that
 * need these:
 *
 * - the master/host side Linux-USB kernel driver API;
 * - the "usbfs" user space API; and
 * - the Linux "gadget" slave/device/peripheral side driver API.
 *
 * USB 2.0 adds an additional "On The Go" (OTG) mode, which lets systems
 * act either as a USB master/host or as a USB slave/device.  That means
 * the master and slave side APIs benefit from working well together.
 *
 * There's also "Wireless USB", using low power short range radios for
 * peripheral interconnection but otherwise building on the USB framework.
 *
 * Note all descriptors are declared '__attribute__((packed))' so that:
 *
 * [a] they never get padded, either internally (USB spec writers
 *     probably handled that) or externally;
 *
 * [b] so that accessing bigger-than-a-bytes fields will never
 *     generate bus errors on any platform, even when the location of
 *     its descriptor inside a bundle isn't "naturally aligned", and
 *
 * [c] for consistency, removing all doubt even when it appears to
 *     someone that the two other points are non-issues for that
 *     particular descriptor type.
 */

#ifndef __LINUX_USB_CH9_H
#define __LINUX_USB_CH9_H

#include <linux/types.h>	/* __u8 etc */

/*-------------------------------------------------------------------------*/

/* CONTROL REQUEST SUPPORT */

/*
 * USB directions
 *
 * This bit flag is used in endpoint descriptors' bEndpointAddress field.
 * It's also one of three fields in control requests bRequestType.
 */
#define USB_DIR_OUT			0		/* to device */
#define USB_DIR_IN			0x80		/* to host */

/*
 * USB types, the second of three bRequestType fields
 */
#define USB_TYPE_MASK			(0x03 << 5)
#define USB_TYPE_STANDARD		(0x00 << 5)
#define USB_TYPE_CLASS			(0x01 << 5)
#define USB_TYPE_VENDOR			(0x02 << 5)
#define USB_TYPE_RESERVED		(0x03 << 5)

/*
 * USB recipients, the third of three bRequestType fields
 */
#define USB_RECIP_MASK			0x1f
#define USB_RECIP_DEVICE		0x00
#define USB_RECIP_INTERFACE		0x01
#define USB_RECIP_ENDPOINT		0x02
#define USB_RECIP_OTHER			0x03
/* From Wireless USB 1.0 */
#define USB_RECIP_PORT 			0x04
#define USB_RECIP_RPIPE 		0x05

/*
 * Standard requests, for the bRequest field of a SETUP packet.
 *
 * These are qualified by the bRequestType field, so that for example
 * TYPE_CLASS or TYPE_VENDOR specific feature flags could be retrieved
 * by a GET_STATUS request.
 */
#define USB_REQ_GET_STATUS		0x00
#define USB_REQ_CLEAR_FEATURE		0x01
#define USB_REQ_SET_FEATURE		0x03
#define USB_REQ_SET_ADDRESS		0x05
#define USB_REQ_GET_DESCRIPTOR		0x06
#define USB_REQ_SET_DESCRIPTOR		0x07
#define USB_REQ_GET_CONFIGURATION	0x08
#define USB_REQ_SET_CONFIGURATION	0x09
#define USB_REQ_GET_INTERFACE		0x0A
#define USB_REQ_SET_INTERFACE		0x0B
#define USB_REQ_SYNCH_FRAME		0x0C

#define USB_REQ_SET_ENCRYPTION		0x0D	/* Wireless USB */
#define USB_REQ_GET_ENCRYPTION		0x0E
#define USB_REQ_RPIPE_ABORT		0x0E
#define USB_REQ_SET_HANDSHAKE		0x0F
#define USB_REQ_RPIPE_RESET		0x0F
#define USB_REQ_GET_HANDSHAKE		0x10
#define USB_REQ_SET_CONNECTION		0x11
#define USB_REQ_SET_SECURITY_DATA	0x12
#define USB_REQ_GET_SECURITY_DATA	0x13
#define USB_REQ_SET_WUSB_DATA		0x14
#define USB_REQ_LOOPBACK_DATA_WRITE	0x15
#define USB_REQ_LOOPBACK_DATA_READ	0x16
#define USB_REQ_SET_INTERFACE_DS	0x17

/*
 * USB feature flags are written using USB_REQ_{CLEAR,SET}_FEATURE, and
 * are read as a bit array returned by USB_REQ_GET_STATUS.  (So there
 * are at most sixteen features of each type.)
 */
#define USB_DEVICE_SELF_POWERED		0	/* (read only) */
#define USB_DEVICE_REMOTE_WAKEUP	1	/* dev may initiate wakeup */
#define USB_DEVICE_TEST_MODE		2	/* (wired high speed only) */
#define USB_DEVICE_BATTERY		2	/* (wireless) */
#define USB_DEVICE_B_HNP_ENABLE		3	/* (otg) dev may initiate HNP */
#define USB_DEVICE_WUSB_DEVICE		3	/* (wireless)*/
#define USB_DEVICE_A_HNP_SUPPORT	4	/* (otg) RH port supports HNP */
#define USB_DEVICE_A_ALT_HNP_SUPPORT	5	/* (otg) other RH port does */
#define USB_DEVICE_DEBUG_MODE		6	/* (special devices only) */

#define USB_ENDPOINT_HALT		0	/* IN/OUT will STALL */


/**
 * struct usb_ctrlrequest - SETUP data for a USB device control request
 * @bRequestType: matches the USB bmRequestType field
 * @bRequest: matches the USB bRequest field
 * @wValue: matches the USB wValue field (le16 byte order)
 * @wIndex: matches the USB wIndex field (le16 byte order)
 * @wLength: matches the USB wLength field (le16 byte order)
 *
 * This structure is used to send control requests to a USB device.  It matches
 * the different fields of the USB 2.0 Spec section 9.3, table 9-2.  See the
 * USB spec for a fuller description of the different fields, and what they are
 * used for.
 *
 * Note that the driver for any interface can issue control requests.
 * For most devices, interfaces don't coordinate with each other, so
 * such requests may be made at any time.
 */
struct usb_ctrlrequest 
{
	//D7: ���ƴ���� DATA transaction �׶εķ���,0 ��ʾ����Ϊ�������豸,1 ��ʾ����Ϊ�豸������.
	//(��ʱ���ƴ������ SETUP transaction �׶�����,���ܻ��� DATA transaction �׶�,�˴���ʾ������ DATA transaction �׶εĴ��䷽��.)
	//D6...5: ���������, 0 ��Ϊ��׼����(Standard),1 ��Ϊ Class,2 ��Ϊ Vendor,3 ���Ǳ�����,����ʹ��.
	//D4...0: ������, 0 ��ʾ�豸,1 ��ʾ�ӿ�,2 ��ʾ�˵�,3 ��ʾ����,4...31 ���Ǳ�����,����ʹ��.
	__u8 bRequestType;
	//ָ�������ĸ�����(request). ÿһ��������һ�����,
	__u8 bRequest;
	//����Ĳ�������ͬ�����в�ͬ��ֵ
	__le16 wValue;
	//����Ĳ���
	//bRequestType ָ��������Ե����豸�ϵ�ĳ���ӿڻ�˵��ʱ�� wIndex ������ָ�����ĸ��ӿڻ�˵�
	__le16 wIndex;
	//���ƴ�����DATA transaction �׶δ�������ݵĳ���(bytes)�������Ѿ���bRequestType ��ָ���ˡ�
	//������ֵΪ 0���ͱ�ʾû�� DATA transaction �׶Σ�bRequestType �ķ���λҲ����Ч��
	__le16 wLength;
} __attribute__ ((packed));

/*-------------------------------------------------------------------------*/

/*
 * STANDARD DESCRIPTORS ... as returned by GET_DESCRIPTOR, or
 * (rarely) accepted by SET_DESCRIPTOR.
 *
 * Note that all multi-byte values here are encoded in little endian
 * byte order "on the wire".  But when exposed through Linux-USB APIs,
 * they've been converted to cpu byte order.
 */

/*
 * Descriptor types ... USB 2.0 spec table 9.5
 */
#define USB_DT_DEVICE			0x01
#define USB_DT_CONFIG			0x02
#define USB_DT_STRING			0x03
#define USB_DT_INTERFACE		0x04
#define USB_DT_ENDPOINT			0x05
#define USB_DT_DEVICE_QUALIFIER		0x06
//�����豸�����ڵ��ٻ�ȫ��ģʽʱ��������Ϣ���������������Ľṹ��ȫ��ͬ������ֻ�������������Ͳ�ͬ
#define USB_DT_OTHER_SPEED_CONFIG	0x07
#define USB_DT_INTERFACE_POWER		0x08
/* these are from a minor usb 2.0 revision (ECN) */
#define USB_DT_OTG			0x09
#define USB_DT_DEBUG			0x0a
#define USB_DT_INTERFACE_ASSOCIATION	0x0b
/* these are from the Wireless USB spec */
#define USB_DT_SECURITY			0x0c
#define USB_DT_KEY			0x0d
#define USB_DT_ENCRYPTION_TYPE		0x0e
#define USB_DT_BOS			0x0f
#define USB_DT_DEVICE_CAPABILITY	0x10
#define USB_DT_WIRELESS_ENDPOINT_COMP	0x11
#define USB_DT_WIRE_ADAPTER		0x21
#define USB_DT_RPIPE			0x22

/* Conventional codes for class-specific descriptors.  The convention is
 * defined in the USB "Common Class" Spec (3.11).  Individual class specs
 * are authoritative for their usage, not the "common class" writeup.
 */
#define USB_DT_CS_DEVICE		(USB_TYPE_CLASS | USB_DT_DEVICE)
#define USB_DT_CS_CONFIG		(USB_TYPE_CLASS | USB_DT_CONFIG)
#define USB_DT_CS_STRING		(USB_TYPE_CLASS | USB_DT_STRING)
#define USB_DT_CS_INTERFACE		(USB_TYPE_CLASS | USB_DT_INTERFACE)
#define USB_DT_CS_ENDPOINT		(USB_TYPE_CLASS | USB_DT_ENDPOINT)

/* All standard descriptors have these 2 fields at the beginning */
struct usb_descriptor_header 
{
	__u8  bLength;
	__u8  bDescriptorType;
} __attribute__ ((packed));


/*-------------------------------------------------------------------------*/

/* USB_DT_DEVICE: Device descriptor */
struct usb_device_descriptor 
{
	__u8  bLength;
	__u8  bDescriptorType;
	//USB spec�İ汾��
	//һ���豸����ܹ����и��ٴ��䣬��ô���豸��������� bcdUSB ��һ���Ӧ��Ϊ 0200H
	__le16 bcdUSB;
	//�ֱ����豸����,�����Э��,������ USB ��̳���䲢������ USB �淶��. 
	//��Щֵָ������豸����Ϊ, �����豸�����еĽӿ�
	__u8  bDeviceClass;
	__u8  bDeviceSubClass;
	__u8  bDeviceProtocol;
	//0�Ŷ˵��ܹ����ͻ��߽��յİ������ֵ
	//�˵� 0 ��û��һ��ר�ŵĶ˵�����������Ϊ����Ҫ�������������е����Զ��� spec ��涨���˵ģ�
	//Ȼ��������������˵���ǡ������ϡ�����һ���������ǲ�һ���ģ������ maximum packet size��
	//ÿ���˵㶼����ôһ�����ԣ���������ö˵��ܹ����ͻ��߽��յİ������ֵ��
	//����ͨ���Ķ˵���˵�����ֵ�������ڸö˵��������е�wMaxPacketSize ��һ�� field��
	//�����ڶ˵� 0 �Ͳ�һ���ˣ��������Լ�û��һ������������ÿ���豸�ֶ�����ôһ���˵㣬
	//���������Ϣ�����������豸������������������豸����������Կ�����ôһ� bMaxPacketSize0��
	//���� spec ���涨�ˣ����ֵֻ���� 8��16�� 32 ���� 64 ������֮һ��
	//���һ���豸�����ڸ���ģʽ�����ֵ��ֻ���� 64������ǹ����ڵ���ģʽ����ֻ���� 8��ȡ���ֵ�����С�
	__u8  bMaxPacketSize0;
	//USB�豸��������ID������www.usb.org����
	__le16 idVendor;
	//USB�豸�Ĳ�ƷID�����������Զ�
	__le16 idProduct;
	//��ʾ����������ָ���Ĳ�Ʒ�İ汾��
	//��BCD��ķ�ʽ����
	__le16 bcdDevice;
	__u8  iManufacturer;
	__u8  iProduct;
	__u8  iSerialNumber;
	//�豸�ڵ�ǰ�ٶ�ģʽ��֧�ֵ������������е��豸�����ڶ���ٶ�ģʽ�²�����
	//���������ֻ�ǵ�ǰ�ٶ�ģʽ�µ�������Ŀ�������ܵ�������Ŀ��
	__u8  bNumConfigurations;
} __attribute__ ((packed));

#define USB_DT_DEVICE_SIZE		18


/*
 * Device and/or Interface Class codes
 * as found in bDeviceClass or bInterfaceClass
 * and defined by www.usb.org documents
 */
#define USB_CLASS_PER_INTERFACE		0	/* for DeviceClass */
#define USB_CLASS_AUDIO			1
#define USB_CLASS_COMM			2
#define USB_CLASS_HID			3
#define USB_CLASS_PHYSICAL		5
#define USB_CLASS_STILL_IMAGE		6
#define USB_CLASS_PRINTER		7
#define USB_CLASS_MASS_STORAGE		8
#define USB_CLASS_HUB			9
#define USB_CLASS_CDC_DATA		0x0a
#define USB_CLASS_CSCID			0x0b	/* chip+ smart card */
#define USB_CLASS_CONTENT_SEC		0x0d	/* content security */
#define USB_CLASS_VIDEO			0x0e
#define USB_CLASS_WIRELESS_CONTROLLER	0xe0
#define USB_CLASS_MISC			0xef
#define USB_CLASS_APP_SPEC		0xfe
#define USB_CLASS_VENDOR_SPEC		0xff

/*-------------------------------------------------------------------------*/

/* USB_DT_CONFIG: Configuration descriptor information.
 *
 * USB_DT_OTHER_SPEED_CONFIG is the same descriptor, except that the
 * descriptor type is different.  Highspeed-capable devices can look
 * different depending on what speed they're currently running.  Only
 * devices with a USB_DT_DEVICE_QUALIFIER have any OTHER_SPEED_CONFIG
 * descriptors.
 */
struct usb_config_descriptor 
{
	__u8  bLength;
	__u8  bDescriptorType;

	//ʹ�� GET_DESCRIPTOR ������豸����������������Ϣʱ�����ص����ݳ��ȣ�
	//Ҳ����˵�԰����������������ӿ����������˵���������
	//class- ��vendor-specific ���������ڵ��������������˸�����
	__le16 wTotalLength;
	//���ð����Ľӿ���Ŀ
	__u8  bNumInterfaces;
	//����ӵ�ж�����õ��豸��˵�����������ֵΪ���� �� 
	//ʹ��SET_CONFIGURATION �������ı����ڱ�ʹ�õ�USB���� ��
	//bConfigurationValue ��ָ���˽�Ҫ������Ǹ����á�
	__u8  bConfigurationValue;
	//����������Ϣ���ַ���������������ֵ
	__u8  iConfiguration;
	//bit 7 spec�涨����Ϊ1
	//bit 6 ��ʾ��ǰ�����Ƿ�֧��self-powered
	//bit 5 ��ʾ��ǰ�����Ƿ�֧��Զ�̻���
	__u8  bmAttributes;
	//���������ĵ����������䵥λ��2mA
	__u8  bMaxPower;
} __attribute__ ((packed));

#define USB_DT_CONFIG_SIZE		9

/* from config descriptor bmAttributes */
#define USB_CONFIG_ATT_ONE		(1 << 7)	/* must be set */
#define USB_CONFIG_ATT_SELFPOWER	(1 << 6)	/* self powered */
#define USB_CONFIG_ATT_WAKEUP		(1 << 5)	/* can wakeup */
#define USB_CONFIG_ATT_BATTERY		(1 << 4)	/* battery powered */

/*-------------------------------------------------------------------------*/

/* USB_DT_STRING: String descriptor */
struct usb_string_descriptor 
{
	__u8  bLength;
	__u8  bDescriptorType;

	__le16 wData[1];		/* UTF-16LE encoded */
} __attribute__ ((packed));

/* note that "string" zero is special, it holds language codes that
 * the device supports, not Unicode characters.
 */

/*-------------------------------------------------------------------------*/

/* USB_DT_INTERFACE: Interface descriptor */
struct usb_interface_descriptor 
{
	//���������ֽڳ���
	//Э����涨��ÿ��������������һ���ֽڴ�ͷ�������������ĳ���
	__u8  bLength;
	//������������(USB_DT_INTERFACE)
	__u8  bDescriptorType;
	//interface���
	//һ�����ÿ����ж��interface��ÿ��interfaceͨ����ͬ���������
	__u8  bInterfaceNumber;
	//setting���
	//�ӿ�ʹ�õ����ĸ���ѡ���á�Э����涨���ӿ�Ĭ��ʹ�õ�������Ϊ0�����á�
	__u8  bAlternateSetting;
	//��ʾ�ӿ�ӵ�еĶ˵����������������в�����0�Ŷ˵㣬
	//0�Ŷ˵����κ�һ��usb�豸�������ṩ�ģ�����˵�ר�����ڽ��п��ƴ��䣬������һ�����ƶ˵㡣
	//����Ϊ���,���Լ�ʹһ���豸û�н����κ�����,usb ����Ҳ���Կ�ʼ��������һЩͨ��,
	//��Ϊ��ʹ��֪�������Ķ˵�,������֪����һ����һ�� 0 �Ŷ˵�,����˵һ�����ƶ˵�
	__u8  bNumEndpoints;
	__u8  bInterfaceClass;
	__u8  bInterfaceSubClass;
	__u8  bInterfaceProtocol;
	//�ӿڶ�Ӧ���ַ���������������ֵ
	//������������Ҫ�����ṩһЩ�豸�ӿ���ص���������Ϣ�� ���糧�̵����֣� ��Ʒ���кŵȵȡ� 
	//������������Ȼ�����ж�������������ֵ���������������ǵġ�
	__u8  iInterface;
} __attribute__ ((packed));

#define USB_DT_INTERFACE_SIZE		9

/*-------------------------------------------------------------------------*/

/* USB_DT_ENDPOINT: Endpoint descriptor */
//���������е�USB�ض������ݣ���Щ���ݵĸ�ʽ�����豸�Լ������
struct usb_endpoint_descriptor 
{
	//���������ֽڳ���
	//Э����涨��ÿ��������������һ���ֽڴ�ͷ�������������ĳ���
	__u8  bLength;
	//������������(USB_DT_ENDPOINT)
	__u8  bDescriptorType;

	//�ض��˵��USB��ַ��
	//���8λ��ֵ�л������˶˵�ķ���
	//���ֶο��Խ��λ����USB_DIR_OUT��USB_DIR_IN��ʹ�ã���ȷ���ö˵�������Ǵ����豸��������
	//bit 0-3 ��ʾ�˵�Ķ˵��
	//      ��ʾ�˵�ĵ�ַ
	//bit 7 ��ʾ�˵�ķ���,0 ��ʾ OUT,1 ��ʾ IN,OUT �� IN �Ƕ���������.OUT ���Ǵ��������豸,IN ���Ǵ��豸������
	__u8  bEndpointAddress;
	//�˵�����͡�
	//��ֵ���Խ��λ����USB_ENDPOINT_XFERTYPE_MASK��ʹ�ã���ȷ���˵������
	//bit 0-1�������� 00��ʾ���ƣ�01��ʾ��ʱ��10��ʾ������11��ʾ�ж�
	__u8  bmAttributes;
	//�ö˵�һ�ο��Դ��������ֽ���
	//ע�⣬����������Է����������ڴ�ֵ�����ݵ��˵㣬
	//������ʵ�ʴ��䵽�豸��ʱ�����ݽ����ָ�ΪwMaxPacketSize��С�Ŀ顣
	//���ڸ����豸��ͨ��ʹ�ø�λ��һЩ�����λ�����ֶο�������֧�ֶ˵�ĸߴ���ģʽ
	__le16 wMaxPacketSize;
	//�ж϶˵������ʱ����
	//����˵����ж����ͣ���ֵ�Ƕ˵��ʱ����--Ҳ����˵���˵���ж�����ʱ����
	//��ֵ�Ժ���Ϊ��λ
	__u8  bInterval;

	/* NOTE:  these two are _only_ in audio endpoints. */
	/* use USB_DT_ENDPOINT*_SIZE in bLength, not sizeof. */
	__u8  bRefresh;
	__u8  bSynchAddress;
} __attribute__ ((packed));

#define USB_DT_ENDPOINT_SIZE		7
#define USB_DT_ENDPOINT_AUDIO_SIZE	9	/* Audio extension */


/*
 * Endpoints
 */
#define USB_ENDPOINT_NUMBER_MASK	0x0f	/* in bEndpointAddress */
#define USB_ENDPOINT_DIR_MASK		0x80

#define USB_ENDPOINT_XFERTYPE_MASK	0x03	/* in bmAttributes */
//���ƶ˵�
#define USB_ENDPOINT_XFER_CONTROL	0
//��ʱ�˵�
#define USB_ENDPOINT_XFER_ISOC		1
//�����˵�
#define USB_ENDPOINT_XFER_BULK		2
//�ж϶˵�
#define USB_ENDPOINT_XFER_INT		3
#define USB_ENDPOINT_MAX_ADJUSTABLE	0x80


/*-------------------------------------------------------------------------*/

/* USB_DT_DEVICE_QUALIFIER: Device Qualifier descriptor */
//������һ�������豸�ڽ����ٶ��л�ʱ����ı����Ϣ
//һ���豸��ǰ������ȫ��״̬,��ô device qualifier �оͱ�������Ϣ��¼����豸�����ڸ���״̬����Ϣ,
//��֮���һ���豸��ǰ�����ڸ���״̬,��ô device qualifier �оͰ���������豸������ȫ��״̬����Ϣ
struct usb_qualifier_descriptor 
{
	__u8  bLength;
	__u8  bDescriptorType;

	__le16 bcdUSB;
	__u8  bDeviceClass;
	__u8  bDeviceSubClass;
	__u8  bDeviceProtocol;
	__u8  bMaxPacketSize0;
	__u8  bNumConfigurations;
	__u8  bRESERVED;
} __attribute__ ((packed));


/*-------------------------------------------------------------------------*/

/* USB_DT_OTG (from OTG 1.0a supplement) */
struct usb_otg_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;

	__u8  bmAttributes;	/* support for HNP, SRP, etc */
} __attribute__ ((packed));

/* from usb_otg_descriptor.bmAttributes */
#define USB_OTG_SRP		(1 << 0)
#define USB_OTG_HNP		(1 << 1)	/* swap host/device roles */

/*-------------------------------------------------------------------------*/

/* USB_DT_DEBUG:  for special highspeed devices, replacing serial console */
struct usb_debug_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;

	/* bulk endpoints with 8 byte maxpacket */
	__u8  bDebugInEndpoint;
	__u8  bDebugOutEndpoint;
} __attribute__((packed));

/*-------------------------------------------------------------------------*/

/* USB_DT_INTERFACE_ASSOCIATION: groups interfaces */
struct usb_interface_assoc_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;

	__u8  bFirstInterface;
	__u8  bInterfaceCount;
	__u8  bFunctionClass;
	__u8  bFunctionSubClass;
	__u8  bFunctionProtocol;
	__u8  iFunction;
} __attribute__ ((packed));


/*-------------------------------------------------------------------------*/

/* USB_DT_SECURITY:  group of wireless security descriptors, including
 * encryption types available for setting up a CC/association.
 */
struct usb_security_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;

	__le16 wTotalLength;
	__u8  bNumEncryptionTypes;
} __attribute__((packed));

/*-------------------------------------------------------------------------*/

/* USB_DT_KEY:  used with {GET,SET}_SECURITY_DATA; only public keys
 * may be retrieved.
 */
struct usb_key_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;

	__u8  tTKID[3];
	__u8  bReserved;
	__u8  bKeyData[0];
} __attribute__((packed));

/*-------------------------------------------------------------------------*/

/* USB_DT_ENCRYPTION_TYPE:  bundled in DT_SECURITY groups */
struct usb_encryption_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;

	__u8  bEncryptionType;
#define	USB_ENC_TYPE_UNSECURE		0
#define	USB_ENC_TYPE_WIRED		1	/* non-wireless mode */
#define	USB_ENC_TYPE_CCM_1		2	/* aes128/cbc session */
#define	USB_ENC_TYPE_RSA_1		3	/* rsa3072/sha1 auth */
	__u8  bEncryptionValue;		/* use in SET_ENCRYPTION */
	__u8  bAuthKeyIndex;
} __attribute__((packed));


/*-------------------------------------------------------------------------*/

/* USB_DT_BOS:  group of wireless capabilities */
struct usb_bos_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;

	__le16 wTotalLength;
	__u8  bNumDeviceCaps;
} __attribute__((packed));

/*-------------------------------------------------------------------------*/

/* USB_DT_DEVICE_CAPABILITY:  grouped with BOS */
struct usb_dev_cap_header {
	__u8  bLength;
	__u8  bDescriptorType;
	__u8  bDevCapabilityType;
} __attribute__((packed));

#define	USB_CAP_TYPE_WIRELESS_USB	1

struct usb_wireless_cap_descriptor {	/* Ultra Wide Band */
	__u8  bLength;
	__u8  bDescriptorType;
	__u8  bDevCapabilityType;

	__u8  bmAttributes;
#define	USB_WIRELESS_P2P_DRD		(1 << 1)
#define	USB_WIRELESS_BEACON_MASK	(3 << 2)
#define	USB_WIRELESS_BEACON_SELF	(1 << 2)
#define	USB_WIRELESS_BEACON_DIRECTED	(2 << 2)
#define	USB_WIRELESS_BEACON_NONE	(3 << 2)
	__le16 wPHYRates;	/* bit rates, Mbps */
#define	USB_WIRELESS_PHY_53		(1 << 0)	/* always set */
#define	USB_WIRELESS_PHY_80		(1 << 1)
#define	USB_WIRELESS_PHY_107		(1 << 2)	/* always set */
#define	USB_WIRELESS_PHY_160		(1 << 3)
#define	USB_WIRELESS_PHY_200		(1 << 4)	/* always set */
#define	USB_WIRELESS_PHY_320		(1 << 5)
#define	USB_WIRELESS_PHY_400		(1 << 6)
#define	USB_WIRELESS_PHY_480		(1 << 7)
	__u8  bmTFITXPowerInfo;	/* TFI power levels */
	__u8  bmFFITXPowerInfo;	/* FFI power levels */
	__le16 bmBandGroup;
	__u8  bReserved;
} __attribute__((packed));

/*-------------------------------------------------------------------------*/

/* USB_DT_WIRELESS_ENDPOINT_COMP:  companion descriptor associated with
 * each endpoint descriptor for a wireless device
 */
struct usb_wireless_ep_comp_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;

	__u8  bMaxBurst;
	__u8  bMaxSequence;
	__le16 wMaxStreamDelay;
	__le16 wOverTheAirPacketSize;
	__u8  bOverTheAirInterval;
	__u8  bmCompAttributes;
#define USB_ENDPOINT_SWITCH_MASK	0x03	/* in bmCompAttributes */
#define USB_ENDPOINT_SWITCH_NO		0
#define USB_ENDPOINT_SWITCH_SWITCH	1
#define USB_ENDPOINT_SWITCH_SCALE	2
} __attribute__((packed));

/*-------------------------------------------------------------------------*/

/* USB_REQ_SET_HANDSHAKE is a four-way handshake used between a wireless
 * host and a device for connection set up, mutual authentication, and
 * exchanging short lived session keys.  The handshake depends on a CC.
 */
struct usb_handshake {
	__u8 bMessageNumber;
	__u8 bStatus;
	__u8 tTKID[3];
	__u8 bReserved;
	__u8 CDID[16];
	__u8 nonce[16];
	__u8 MIC[8];
} __attribute__((packed));

/*-------------------------------------------------------------------------*/

/* USB_REQ_SET_CONNECTION modifies or revokes a connection context (CC).
 * A CC may also be set up using non-wireless secure channels (including
 * wired USB!), and some devices may support CCs with multiple hosts.
 */
struct usb_connection_context {
	__u8 CHID[16];		/* persistent host id */
	__u8 CDID[16];		/* device id (unique w/in host context) */
	__u8 CK[16];		/* connection key */
} __attribute__((packed));

/*-------------------------------------------------------------------------*/

/* USB 2.0 defines three speeds, here's how Linux identifies them */

enum usb_device_speed 
{
	//��ʾ�ֽ׶λ���֪������豸����ʲô�ٶ�
	USB_SPEED_UNKNOWN = 0,			/* enumerating */
	USB_SPEED_LOW, USB_SPEED_FULL,		/* usb 1.1 */
	USB_SPEED_HIGH,				/* usb 2.0 */
	USB_SPEED_VARIABLE,			/* wireless (usb 2.5) */
};

enum usb_device_state 
{
	/* NOTATTACHED isn't in the USB spec, and this state acts
	 * the same as ATTACHED ... but it's clearer this way.
	 */
	USB_STATE_NOTATTACHED = 0,

	/* chapter 9 and authentication (wireless) device states */
	//��ʾ�豸�����ӵ�usb�ӿ����ˣ���hub��⵽�豸ʱ�ĳ�ʼ״̬
	USB_STATE_ATTACHED,
	
	USB_STATE_POWERED,			/* wired */
	USB_STATE_UNAUTHENTICATED,		/* auth */
	USB_STATE_RECONNECTING,			/* auth */
	//Default ȱʡ״̬���� Powered ֮���豸�������յ�һ����λ��reset���źŲ��ɹ���λ��
	//����ʹ��ȱʡ��ַ��Ӧ�������������豸������������������
	USB_STATE_DEFAULT,			/* limited function */
	//��ʾ����������һ��Ψһ�ĵ�ַ���豸����ʱ�豸����ʹ��ȱʡ�ܵ���Ӧ����������
	USB_STATE_ADDRESS,
	//��ʾ�豸�Ѿ����������ù��ˣ�Ҳ����Э����˵�Ĵ�����һ�����з�0ֵ�� SetConfiguration()����
	//��ʱ��������ʹ���豸�ṩ�����й���
	USB_STATE_CONFIGURED,			/* most functions */
	//����״̬��Ϊ��ʡ�磬�豸��ָ����ʱ���ڣ����û�з������ߴ��䣬��Ҫ�������״̬��
	//��ʱ�� usb �豸Ҫ�Լ�ά��������ַ���������ڵ���Ϣ
	USB_STATE_SUSPENDED

	/* NOTE:  there are actually four different SUSPENDED
	 * states, returning to POWERED, DEFAULT, ADDRESS, or
	 * CONFIGURED respectively when SOF tokens flow again.
	 */
};

#endif	/* __LINUX_USB_CH9_H */
