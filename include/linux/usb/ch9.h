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
	//D7: 控制传输的 DATA transaction 阶段的方向,0 表示方向为主机到设备,1 表示方向为设备到主机.
	//(有时控制传输除了 SETUP transaction 阶段以外,可能还有 DATA transaction 阶段,此处表示的是在 DATA transaction 阶段的传输方向.)
	//D6...5: 请求的类型, 0 称为标准类型(Standard),1 称为 Class,2 称为 Vendor,3 则是保留的,不能使用.
	//D4...0: 接收者, 0 表示设备,1 表示接口,2 表示端点,3 表示其它,4...31 都是保留的,不能使用.
	__u8 bRequestType;
	//指定了是哪个请求(request). 每一个请求都有一个编号,
	__u8 bRequest;
	//请求的参数，不同请求有不同的值
	__le16 wValue;
	//请求的参数
	//bRequestType 指明请求针对的是设备上的某个接口或端点的时候， wIndex 就用来指明是哪个接口或端点
	__le16 wIndex;
	//控制传输中DATA transaction 阶段传输的数据的长度(bytes)，方向已经在bRequestType 中指明了。
	//如果这个值为 0，就表示没有 DATA transaction 阶段，bRequestType 的方向位也就无效了
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
//高速设备操作在低速或全速模式时的配置信息，和配置描述符的结构完全相同，区别只是描述符的类型不同
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
	//USB spec的版本号
	//一个设备如果能够进行高速传输，那么它设备描述符里的 bcdUSB 这一项就应该为 0200H
	__le16 bcdUSB;
	//分别定义设备的类,子类和协议,他们由 USB 论坛分配并定义在 USB 规范中. 
	//这些值指定这个设备的行为, 包括设备上所有的接口
	__u8  bDeviceClass;
	__u8  bDeviceSubClass;
	__u8  bDeviceProtocol;
	//0号端点能够发送或者接收的包的最大值
	//端点 0 并没有一个专门的端点描述符，因为不需要，基本上它所有的特性都在 spec 里规定好了的，
	//然而，别忘了这里说的是“基本上”，有一个特性则是不一样的，这叫做 maximum packet size，
	//每个端点都有这么一个特性，即告诉你该端点能够发送或者接收的包的最大值。
	//对于通常的端点来说，这个值被保存在该端点描述符中的wMaxPacketSize 这一个 field，
	//而对于端点 0 就不一样了，由于它自己没有一个描述符，而每个设备又都有这么一个端点，
	//所以这个信息被保存在了设备描述符里，所以我们在设备描述符里可以看到这么一项， bMaxPacketSize0。
	//而且 spec 还规定了，这个值只能是 8，16， 32 或者 64 这四者之一，
	//如果一个设备工作在高速模式，这个值还只能是 64，如果是工作在低速模式，则只能是 8，取别的值都不行。
	__u8  bMaxPacketSize0;
	//USB设备的制造商ID，须向www.usb.org申请
	__le16 idVendor;
	//USB设备的产品ID，由制造商自定
	__le16 idProduct;
	//表示的是制造商指定的产品的版本号
	//以BCD码的方式保存
	__le16 bcdDevice;
	__u8  iManufacturer;
	__u8  iProduct;
	__u8  iSerialNumber;
	//设备在当前速度模式下支持的配置数量。有的设备可以在多个速度模式下操作，
	//这里包括的只是当前速度模式下的配置数目，不是总的配置数目。
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

	//使用 GET_DESCRIPTOR 请求从设备里获得配置描述符信息时，返回的数据长度，
	//也就是说对包括配置描述符、接口描述符、端点描述符，
	//class- 或vendor-specific 描述符在内的所有描述符算了个总帐
	__le16 wTotalLength;
	//配置包含的接口数目
	__u8  bNumInterfaces;
	//对于拥有多个配置的设备来说，可以拿这个值为参数 ， 
	//使用SET_CONFIGURATION 请求来改变正在被使用的USB配置 ，
	//bConfigurationValue 就指明了将要激活的那个配置。
	__u8  bConfigurationValue;
	//描述配置信息的字符串描述符的索引值
	__u8  iConfiguration;
	//bit 7 spec规定必须为1
	//bit 6 表示当前配置是否支持self-powered
	//bit 5 表示当前配置是否支持远程唤醒
	__u8  bmAttributes;
	//该配置消耗的最大电流，其单位是2mA
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
	//描述符的字节长度
	//协议里规定，每个描述符必须以一个字节打头来表明描述符的长度
	__u8  bLength;
	//描述符的类型(USB_DT_INTERFACE)
	__u8  bDescriptorType;
	//interface编号
	//一个配置可以有多个interface，每个interface通过不同编号来区分
	__u8  bInterfaceNumber;
	//setting编号
	//接口使用的是哪个可选设置。协议里规定，接口默认使用的设置总为0号设置。
	__u8  bAlternateSetting;
	//表示接口拥有的端点数量，不过这其中不包括0号端点，
	//0号端点是任何一个usb设备都必须提供的，这个端点专门用于进行控制传输，即它是一个控制端点。
	//正因为如此,所以即使一个设备没有进行任何设置,usb 主机也可以开始跟它进行一些通信,
	//因为即使不知道其它的端点,但至少知道它一定有一个 0 号端点,或者说一个控制端点
	__u8  bNumEndpoints;
	__u8  bInterfaceClass;
	__u8  bInterfaceSubClass;
	__u8  bInterfaceProtocol;
	//接口对应的字符串描述符的索引值
	//符串描述符主要就是提供一些设备接口相关的描述性信息， 比如厂商的名字， 产品序列号等等。 
	//符串描述符当然可以有多个，这里的索引值就是用来区分它们的。
	__u8  iInterface;
} __attribute__ ((packed));

#define USB_DT_INTERFACE_SIZE		9

/*-------------------------------------------------------------------------*/

/* USB_DT_ENDPOINT: Endpoint descriptor */
//包含了所有的USB特定的数据，这些数据的格式是由设备自己定义的
struct usb_endpoint_descriptor 
{
	//描述符的字节长度
	//协议里规定，每个描述符必须以一个字节打头来表明描述符的长度
	__u8  bLength;
	//描述符的类型(USB_DT_ENDPOINT)
	__u8  bDescriptorType;

	//特定端点的USB地址。
	//这个8位的值中还包含了端点的方向。
	//该字段可以结合位掩码USB_DIR_OUT和USB_DIR_IN来使用，以确定该端点的数据是传向设备还是主机
	//bit 0-3 表示端点的端点号
	//      表示端点的地址
	//bit 7 表示端点的方向,0 表示 OUT,1 表示 IN,OUT 与 IN 是对主机而言.OUT 就是从主机到设备,IN 就是从设备到主机
	__u8  bEndpointAddress;
	//端点的类型。
	//该值可以结合位掩码USB_ENDPOINT_XFERTYPE_MASK来使用，以确定端点的类型
	//bit 0-1传输类型 00表示控制，01表示等时，10表示批量，11表示中断
	__u8  bmAttributes;
	//该端点一次可以处理的最大字节数
	//注意，驱动程序可以发送数量大于此值的数据到端点，
	//但是在实际传输到设备的时候，数据将被分割为wMaxPacketSize大小的块。
	//对于高速设备，通过使用高位中一些额外的位，该字段可以用来支持端点的高带宽模式
	__le16 wMaxPacketSize;
	//中断端点的请求时间间隔
	//如果端点是中断类型，该值是端点的时间间隔--也就是说，端点的中断请求时间间隔
	//该值以毫秒为单位
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
//控制端点
#define USB_ENDPOINT_XFER_CONTROL	0
//等时端点
#define USB_ENDPOINT_XFER_ISOC		1
//批量端点
#define USB_ENDPOINT_XFER_BULK		2
//中断端点
#define USB_ENDPOINT_XFER_INT		3
#define USB_ENDPOINT_MAX_ADJUSTABLE	0x80


/*-------------------------------------------------------------------------*/

/* USB_DT_DEVICE_QUALIFIER: Device Qualifier descriptor */
//描述了一个高速设备在进行速度切换时所需改变的信息
//一个设备当前工作于全速状态,那么 device qualifier 中就保存着信息记录这个设备工作在高速状态的信息,
//反之如果一个设备当前工作于高速状态,那么 device qualifier 中就包含着这个设备工作于全速状态的信息
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
	//表示现阶段还不知道这个设备究竟什么速度
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
	//表示设备已连接到usb接口上了，是hub检测到设备时的初始状态
	USB_STATE_ATTACHED,
	
	USB_STATE_POWERED,			/* wired */
	USB_STATE_UNAUTHENTICATED,		/* auth */
	USB_STATE_RECONNECTING,			/* auth */
	//Default 缺省状态，在 Powered 之后，设备必须在收到一个复位（reset）信号并成功复位后，
	//才能使用缺省地址回应主机发过来的设备和配置描述符的请求。
	USB_STATE_DEFAULT,			/* limited function */
	//表示主机分配了一个唯一的地址给设备，此时设备可以使用缺省管道响应主机的请求
	USB_STATE_ADDRESS,
	//表示设备已经被主机配置过了，也就是协议里说的处理了一个带有非0值的 SetConfiguration()请求，
	//此时主机可以使用设备提供的所有功能
	USB_STATE_CONFIGURED,			/* most functions */
	//挂起状态，为了省电，设备在指定的时间内，如果没有发生总线传输，就要进入挂起状态。
	//此时， usb 设备要自己维护包括地址、配置在内的信息
	USB_STATE_SUSPENDED

	/* NOTE:  there are actually four different SUSPENDED
	 * states, returning to POWERED, DEFAULT, ADDRESS, or
	 * CONFIGURED respectively when SOF tokens flow again.
	 */
};

#endif	/* __LINUX_USB_CH9_H */
