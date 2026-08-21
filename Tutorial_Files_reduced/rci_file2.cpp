//
//  rci_messagetunnelandroid.cpp
//  SkyBluetoothRcu
//
//  Copyright © 2018 Sky UK. All rights reserved.
//

#include "rci_messagetunnelandroid.h"
#include "../rci_messagetypes.h"
#include "../rci_messagerequest.h"
#include "../rci_messagereply_p.h"

#include "rci_gatthidservice.h"

#include "blercu/blegattcharacteristic.h"

#include "logging.h"

#include <functional>

// -----------------------------------------------------------------------------
/*!
	\class RciMessageTunnel
	\brief Used to send and receive message to/from the RCU over hid report 15.

	Messages are sent back and forth to the RCU by formatting them as packets
	with a 3 byte header and an optional crc16 appended.  The packets are
	chopped up into 19 byte frames and then sent over hid report number 15.
	The hid report is sized as 20 bytes, so the first byte of the hid report
	contains a header with flags indicating if it's the start of a packet plus
	a 2-bit command counter that increments after every frame.
 
	There are 4 packet types; commands, acknowledgement, negative
	acknowledgement and errors.  Typically commands are sent from host side
	to the rcu, and the rcu will reply with an acknowledgement, negative
	acknowledgement or error. The reply will contain the same command id as
	request.  However the rcu can send unsolicited commands to notify of
	events, ie. battery level changes.

	This object is modelled on the QNetworkManager, it has an asynchronous API.
 
	A simple request / reply could be accomplished with:
	\code
		RciMessageTunnel *tunnel = new RciMessageTunnel(this);
		connect(manager, SIGNAL(finished(QSharedPointer<RciMessageReply>)),
		        this, SLOT(replyFinished(QSharedPointer<RciMessageReply>)));

		RciMessageRequest request(RciMessageCommand::GetManufacturerName);
		manager->send(request);
	\endcode

	When the replyFinished slot above is called, the parameter it takes is the
	QSharedPointer<RciMessageReply> object containing the reply message as
	well as data in the response.
 
	Alternatively you can connect to the finished() signal of the returned
	RciMessageReply object, like in the following example:
	\code
		RciMessageRequest request(RciMessageCommand::RegisterBatteryLevel);
		request.setData({ 0x00, 0x01 })

		QSharedPointer<RciMessageReply> reply = tunnel->send(request);
		connect(reply.data(), SIGNAL(finished()), this, SLOT(slotReplyReceived()));
		connect(reply.data(), SIGNAL(error(RciMessageError)),
		        this, SLOT(slotError(RciMessageError)));
	\endcode

	\note RciMessageTunnel doesn't queue messages of the same command, it only
	allows one outstanding request per command at a time. send() will return
	\c false if a message reply for the same command is pending.
 
	\note RciMessageTunnel has a universal timeout of 7 seconds, if no
	reply is received within that period the error slot is called with
	RciMessageTunnel::TimedOut.  7 seconds was chosen because the default slave
	latency on the ruwido RCUs is 5 seconds.

 */


const quint8 RciMessageTunnelAndroid::m_hidReportId = 15;


RciMessageTunnelAndroid::RciMessageTunnelAndroid(const QSharedPointer<RciGattHidService> &hidService,
                                                 QObject *parent)
	: RciMessageTunnel(parent)
	, m_state(ClosedState)
	, m_hidService(hidService)
	, m_defaultTimeout(7000)
	, m_requestIdCounter(1)
	, m_txCmdCounter(0)
	, m_rxCmdCounter(0)
	, m_rxCmdLength(0)
{

	// connect to the 'services resolved' signal of the HID service
	QObject::connect(hidService.data(), &RciGattHidService::serviceResolved,
	                 this, &RciMessageTunnelAndroid::onHidServiceResolved);
}

RciMessageTunnelAndroid::~RciMessageTunnelAndroid()
{
	// abort all requests
	abortAll();

	// clean-up
	m_inputReportCharacteristic.reset();
	m_outputReportCharacteristic.reset();
}

// -----------------------------------------------------------------------------
/*!
	Returns \c true if the tunnel was opened successifully.

 */
bool RciMessageTunnelAndroid::isOpen() const
{
	return (m_state == OpenedState);
}

// -----------------------------------------------------------------------------
/*!
	Attempts to open the tunnel.  This is an async operation, callers should
	connect to the RciMessageTunnel::error() and RciMessageTunnel::open()
	signals to determine the result of the operation.

	The method may fail immediately and return \c false if the tunnel is already
	in the process of opening.

 */
bool RciMessageTunnelAndroid::open()
{
	// check we're in the close state
	if (Q_UNLIKELY(m_state != ClosedState)) {
		qWarning("tunnel already open");
		return false;
	}

	// sanity check we have the GATT hid service
	if (!m_hidService) {
		qError("missing GATT HID service");
		return false;
	}

	// move to the getting descriptors state
	m_state = ResolvingHidServiceState;


	// try and resolve the HID services if not already done
	if (m_hidService->isServiceResolved())
		onHidServiceResolved();
	else
		m_hidService->resolveService();

	return (m_state != ClosedState);
}

// -----------------------------------------------------------------------------
/*!
	\internal

	Called after the all the outstanding descriptor reads has finished (in
	success or error).  This is used to move the state machine on.

 */
void RciMessageTunnelAndroid::onHidServiceResolved()
{
	// ignore if not already in the 'ResolvingHidServiceState' state, ie. the
	// tunnel is closed
	if (m_state != ResolvingHidServiceState)
		return;


	// try and get the input and output report characteristics
	m_inputReportCharacteristic =
		m_hidService->reportCharacteristic(RciGattHidService::InputReport,
		                                   m_hidReportId);

	m_outputReportCharacteristic =
		m_hidService->reportCharacteristic(RciGattHidService::OutputReport,
		                                   m_hidReportId);

	// check we managed to find both the input and output characteristics
	if (!m_inputReportCharacteristic || !m_outputReportCharacteristic) {
		qWarning("failed to find HID report 15 characteristics");

		// clean-up
		m_inputReportCharacteristic.reset();
		m_outputReportCharacteristic.reset();
		m_state = ClosedState;

		// and emit the error
		emit error(MissingHIDReports);
		return;
	}


	// have both characteristics, so move to the 'EnablingNotifications'
	// state ...
	m_state = EnablingNotificationsState;


	// ... connect to the notification signal ...
	QObject::connect(m_inputReportCharacteristic.data(),
	                 &BleGattCharacteristic::valueChanged,
	                 this, &RciMessageTunnelAndroid::onNotification,
	                 Qt::UniqueConnection);

	// .. and request notifications to be enabled
	Future<> result = m_inputReportCharacteristic->enableNotifications(true);
	if (result.isError()) {
		onNotificationsError(result.errorName(), result.errorMessage());
	} else if (result.isFinished()) {
		onNotificationsEnabled();
	} else {
		result.connectFinished(this, &RciMessageTunnelAndroid::onNotificationsEnabled);
		result.connectErrored(this, &RciMessageTunnelAndroid::onNotificationsError);
	}

}

// -----------------------------------------------------------------------------
/*!
	\internal

	Called when the notifications have successifully been enabled.
 */
void RciMessageTunnelAndroid::onNotificationsEnabled()
{
	// sanity check we're in the 'EnablingNotifications' state, if not ignore
	if (Q_UNLIKELY(m_state != EnablingNotificationsState)) {
		qWarning("odd, received result in wrong state (%d)", m_state);
		return;
	}

	// can now move to the enabling state and emit a signal that we're done
	m_state = OpenedState;
	emit opened();
}

// -----------------------------------------------------------------------------
/*!
	\internal

	Called when the notifications have successifully been enabled.
 */
void RciMessageTunnelAndroid::onNotificationsError(const QString &errorName,
                                                   const QString &errorMessage)
{
	Q_UNUSED(errorName);

	qWarning() << "failed to enable notifications due to:" << errorMessage;

	// sanity check we're in the 'EnablingNotifications' state, if not ignore
	if (Q_UNLIKELY(m_state != EnablingNotificationsState)) {
		qWarning("odd, received result in wrong state (%d)", m_state);
		return;
	}

	// clean-up
	m_inputReportCharacteristic.reset();
	m_outputReportCharacteristic.reset();
	m_state = ClosedState;

	// signal the error
	emit error(EnableNotificationsFailed);
}

// -----------------------------------------------------------------------------
/*!
	Closes the tunnel.

	This will cancel any pending requests.

 */
void RciMessageTunnelAndroid::close()
{
	// disconnect from the notification messages and then disable them
	if (m_inputReportCharacteristic) {
		m_inputReportCharacteristic->disconnect(this);
		m_inputReportCharacteristic->enableNotifications(false);
	}

	// clean-up
	m_inputReportCharacteristic.reset();
	m_outputReportCharacteristic.reset();

	if (m_state != ClosedState) {
		m_state = ClosedState;
		emit closed();
	}

	// abort all requests
	abortAll();
}

// -----------------------------------------------------------------------------
/*!
	Sends a request across the tunnel and returns a newly created
	\a RciMessageReply object which emits the \a RciMessageReply::finished()
	signal when a reply is received or an error occurs.

	This object will also emit the \a RciMessageTunnel::finished signal with
	shared pointer to the reply object.


 */
QSharedPointer<RciMessageReply> RciMessageTunnelAndroid::send(const RciMessageRequest &request,
                                                              int timeout, int retries)
{
	// check we're actually open
	if (Q_UNLIKELY(m_state != OpenedState)) {
		qWarning("tunnel has is not open, aborting new send request");
		return QSharedPointer<RciMessageReply>();
	}

	// check if the request queue is full
	if (Q_UNLIKELY(m_outstandingRequests.size() >= 32)) {
		qWarning("tunnel request queue is full");
		return QSharedPointer<RciMessageReply>();
	}

	// check if we already have one of these requests pending
	if (Q_UNLIKELY(m_outstandingRequests.contains(request.command()))) {
		qWarning("tunnel request command already queued");
		return QSharedPointer<RciMessageReply>();
	}


	// set the timeout to the default if not specified
	if (timeout < 0)
		timeout = m_defaultTimeout;

	// create the reply object for the client to listen on
	QSharedPointer<RciMessageReplyImpl> reply =
		QSharedPointer<RciMessageReplyImpl>::create(request);

	// queue up the request
	Request request_ = { ++m_requestIdCounter, timeout, retries, reply };
	m_outstandingRequests.insert(request.command(), std::move(request_));

	// send the request
	if (sendRequest(request) == false) {

		// set the reply error
		reply->setType(RciMessageType::Error);
		reply->setError(RciMessageError::UnknownError);

		// remove from the outstanding request map
		m_outstandingRequests.remove(request.command());

	} else {

		// create a single-shot timer for the timeout, it's attached to a
		// functor so we can add the request id to the timer callback
		std::function<void()> functor = std::bind(&RciMessageTunnelAndroid::onTimeout,
		                                          this, m_requestIdCounter);

		QTimer::singleShot(timeout, this, functor);

	}

	return reply;
}

// -----------------------------------------------------------------------------
/*!
	\internal

	Uses the CRC-16/BUYPASS algorithm to calculate the 16-bit CRC used to
	checksum the messages.

	\see http://www.sunshine2k.de/coding/javascript/crc/crc_js.html for the
	generated CRC table

 */
quint16 RciMessageTunnelAndroid::calculateCrc(const quint8 *data, int dataLen) const
{
	static const quint16 table[256] = {
		0x0000, 0x8005, 0x800f, 0x000a, 0x801b, 0x001e, 0x0014, 0x8011,
		0x8033, 0x0036, 0x003c, 0x8039, 0x0028, 0x802d, 0x8027, 0x0022,
		0x8063, 0x0066, 0x006c, 0x8069, 0x0078, 0x807d, 0x8077, 0x0072,
		0x0050, 0x8055, 0x805f, 0x005a, 0x804b, 0x004e, 0x0044, 0x8041,
		0x80c3, 0x00c6, 0x00cc, 0x80c9, 0x00d8, 0x80dd, 0x80d7, 0x00d2,
		0x00f0, 0x80f5, 0x80ff, 0x00fa, 0x80eb, 0x00ee, 0x00e4, 0x80e1,
		0x00a0, 0x80a5, 0x80af, 0x00aa, 0x80bb, 0x00be, 0x00b4, 0x80b1,
		0x8093, 0x0096, 0x009c, 0x8099, 0x0088, 0x808d, 0x8087, 0x0082,
		0x8183, 0x0186, 0x018c, 0x8189, 0x0198, 0x819d, 0x8197, 0x0192,
		0x01b0, 0x81b5, 0x81bf, 0x01ba, 0x81ab, 0x01ae, 0x01a4, 0x81a1,
		0x01e0, 0x81e5, 0x81ef, 0x01ea, 0x81fb, 0x01fe, 0x01f4, 0x81f1,
		0x81d3, 0x01d6, 0x01dc, 0x81d9, 0x01c8, 0x81cd, 0x81c7, 0x01c2,
		0x0140, 0x8145, 0x814f, 0x014a, 0x815b, 0x015e, 0x0154, 0x8151,
		0x8173, 0x0176, 0x017c, 0x8179, 0x0168, 0x816d, 0x8167, 0x0162,
		0x8123, 0x0126, 0x012c, 0x8129, 0x0138, 0x813d, 0x8137, 0x0132,
		0x0110, 0x8115, 0x811f, 0x011a, 0x810b, 0x010e, 0x0104, 0x8101,
		0x8303, 0x0306, 0x030c, 0x8309, 0x0318, 0x831d, 0x8317, 0x0312,
		0x0330, 0x8335, 0x833f, 0x033a, 0x832b, 0x032e, 0x0324, 0x8321,
		0x0360, 0x8365, 0x836f, 0x036a, 0x837b, 0x037e, 0x0374, 0x8371,
		0x8353, 0x0356, 0x035c, 0x8359, 0x0348, 0x834d, 0x8347, 0x0342,
		0x03c0, 0x83c5, 0x83cf, 0x03ca, 0x83db, 0x03de, 0x03d4, 0x83d1,
		0x83f3, 0x03f6, 0x03fc, 0x83f9, 0x03e8, 0x83ed, 0x83e7, 0x03e2,
		0x83a3, 0x03a6, 0x03ac, 0x83a9, 0x03b8, 0x83bd, 0x83b7, 0x03b2,
		0x0390, 0x8395, 0x839f, 0x039a, 0x838b, 0x038e, 0x0384, 0x8381,
		0x0280, 0x8285, 0x828f, 0x028a, 0x829b, 0x029e, 0x0294, 0x8291,
		0x82b3, 0x02b6, 0x02bc, 0x82b9, 0x02a8, 0x82ad, 0x82a7, 0x02a2,
		0x82e3, 0x02e6, 0x02ec, 0x82e9, 0x02f8, 0x82fd, 0x82f7, 0x02f2,
		0x02d0, 0x82d5, 0x82df, 0x02da, 0x82cb, 0x02ce, 0x02c4, 0x82c1,
		0x8243, 0x0246, 0x024c, 0x8249, 0x0258, 0x825d, 0x8257, 0x0252,
		0x0270, 0x8275, 0x827f, 0x027a, 0x826b, 0x026e, 0x0264, 0x8261,
		0x0220, 0x8225, 0x822f, 0x022a, 0x823b, 0x023e, 0x0234, 0x8231,
		0x8213, 0x0216, 0x021c, 0x8219, 0x0208, 0x820d, 0x8207, 0x0202,
	};

	quint16 crc = 0;

	for (int i = 0; i < dataLen; i++) {

		// XOR-in next input byte into MSB of crc, that's our new intermediate
		// divident
		quint8 lookup = quint8(crc >> 8) ^ data[i];

		// shift out the MSB used for division per lookuptable and XOR with the
		// remainder
		crc = (crc << 8) ^ table[lookup];
	}

	return crc;
}

// -----------------------------------------------------------------------------
/*!
	\internal

	Formats the request message and sends it out the hidraw device interface.


 */
bool RciMessageTunnelAndroid::sendRequest(const RciMessageRequest &request)
{
	// the following is the message format
	//
	//    byte 0  :  bits 7:5   : type (0=cmd, err=1, ack=2, nak=3)
	//    byte 0  :  bit 4      : flag (1=crc)
	//    byte 0  :  bits 3:2   : ?
	//    byte 0  :  bits 1:0   : data length bits 9 and 8
	//    byte 1  :  bits 7:0   : data length bits 7 to 0  (length includes
	//                            3 byte header and 2 byte crc if set)
	//    byte 2  :  bits 7:0   : command
	//     ...    :             : data
	// byte 2 + n :             : crc-16 ccitt if crc flag is set

	// calculate the total length
	int dataLen = request.dataLength();
	int messageLen = 3 + dataLen + 2;

	if (Q_UNLIKELY(messageLen >= 0x400)) {
		qError("message length to large (max:%d, actual:%d)",
		       (0x400 - 1), messageLen);
		return false;
	}

	// populate the data
	QByteArray message;
	message.reserve(messageLen);

	// write the header, see above for format
	message.append( quint8(0x10 | (messageLen >> 8)) );
	message.append( quint8(messageLen & 0xff) );
	message.append( quint8(request.command()) );

	// append all the data
	message.append( request.data() );

	// calculate the crc and then append that as well
	quint16 crc = calculateCrc(reinterpret_cast<const quint8 *>(message.data()),
	                           message.length());
	message.append( quint8((crc >> 0) & 0xff) );
	message.append( quint8((crc >> 8) & 0xff) );



	// we now need to segment up the message so it fits within the 20 byte hid
	// report size, the first byte of the report is formatted like so
	//
	// byte 0  :  bit 7      : RCI_FRAME_FLAG_PUSI - start of data indicator
	// byte 0  :  bit 6      : CSR_PROXY_FIX ?? (always 1)
	// byte 0  :  bits 1:0   : command counter, starts at zero increments
	//                         after every packet
	quint8 report[20];
	bool firstReport = true;
	const quint8* messagePtr = reinterpret_cast<const quint8*>(message.data());

	while (messageLen > 0) {

		memset(report, 0x00, sizeof(report));

		report[0] = 0x40;

		if (firstReport) {
			report[0] |= 0x80;
			firstReport = false;
		}

		report[0] |= m_txCmdCounter & 0x3;
		m_txCmdCounter = (m_txCmdCounter + 1) & 0x3;

		const int amount = qMin<int>(messageLen, 19);
		memcpy(&report[1], messagePtr, amount);

		messagePtr += amount;
		messageLen -= amount;

		// send / queue the report (nb: 'write without response' rather than an
		// ordinary write to match what was done on the SkyQ STB)
		const  QByteArray value(reinterpret_cast<const char*>(report), (1 + amount));
		m_outputReportCharacteristic->writeValueWithoutResponse(value);
	}

	return true;
}


// -----------------------------------------------------------------------------
/*!
	\internal

	Called when a notification is received from the characteristic corresponding
	to the HID input descriptor ... basically the RCU has sent us a frame over
	the HID interface.

 */
void RciMessageTunnelAndroid::onNotification(const QByteArray &value)
{
	qDebug() << "received HID notification" << arrayToHex(value);


	const quint8* report = reinterpret_cast<const quint8*>(value.data());

	// sanity check the data received, it should be at least one byte and no
	// more than 20 bytes
	const int reportLen = value.size();
	if (Q_UNLIKELY((reportLen < 1) || (reportLen > 20))) {
		qWarning("received a RCI frame with invalid size (1 <= %d <= 20)", reportLen);
		return;
	}

	// the data sent by the STB is formatted like
	//
	//    the first byte indicates whether this is a start of a new command
	//    or the rest of an existing command:
	//
	//        byte 0  :  bit 7      : RCI_FRAME_FLAG_PUSI - start of data
	//                                indicator
	//        byte 0  :  bit 6      : CSR_PROXY_FIX ?? (always 1)
	//        byte 0  :  bits 1:0   : command counter, starts at zero increments
	//                                after every packet
	//
	//    then the rest of the frame is part of a packet that is formatted like so
	//
	//        byte 0  :  bits 7:5   : type (0=cmd, err=1, ack=2, nak=3)
	//        byte 0  :  bit 4      : flag (1=crc)
	//        byte 0  :  bits 3:2   : ?
	//        byte 0  :  bits 1:0   : data length bits 9 and 8
	//        byte 1  :  bits 7:0   : data length bits 7 to 0  (length includes
	//                                3 byte header and 2 byte crc if set)
	//        byte 2  :  bits 7:0   : command
	//         ...    :             : data
	//        byte 2 + n :          : crc-16 ccitt if crc flag is set

	// check the CSR_PROXY_FIX bit is set
	// if (Q_UNLIKELY(!(report[0] & 0x40))) {
	// 	qWarning("CSR_PROXY_FIX bit is not set, ignoring frame");
	// 	return;
	// }

	// check the first byte, if it's indicating a new packet then
	if (report[0] & 0x80) {

		// log an error if we were partly through a packet when the start of
		// a new packet came, however we discard the old one and continue on
		if (!m_rxCmdBuffer.isEmpty()) {
			qWarning("received a start of a new packet before completing the "
			         "previous, discarding the old partial one");
		}

		// reset the stats
		m_rxCmdLength = 0;
		m_rxCmdBuffer.clear();

		// we should have at least 3 bytes to cover the header of the new packet
		if (reportLen < 4) {
			qWarning("report data to small (%d bytes) for start of message", reportLen);
			return;
		}

		// calculate the expected length of the packet and reject it if too big
		m_rxCmdLength = (quint16(report[1] & 0x03) << 8) | quint16(report[2]);

		// if the crc flag is set, make sure the packet is at least 5 bytes
		if ((report[1] & 0x10) && (m_rxCmdLength < 5)) {
			qWarning("message length (%d bytes) to short to include crc", m_rxCmdLength);
			return;
		}

	// else check that we've actually received the start of the packet
	} else if (m_rxCmdBuffer.isEmpty()) {
		qWarning("missed start or previous report was corrupt");
		return;

	// else check if the command counter is correct
	} else if (m_rxCmdCounter != (report[0] & 0x03)) {
		qWarning("invalid command counter (expected=%u, actual=%u",
		         m_rxCmdCounter, (report[0] & 0x03));
		m_rxCmdBuffer.clear();
		return;
	}

	// set the next expected command counter value
	m_rxCmdCounter = (report[0] + 1) & 0x03;

	// everything checks out so append the data into the buffer
	m_rxCmdBuffer.append(reinterpret_cast<const char*>(report + 1),
	                     (reportLen - 1));


	// check if this is the end of the packet
	if (m_rxCmdBuffer.size() >= m_rxCmdLength) {

		// truncate the command buffer if the rcu sent to much
		if (m_rxCmdBuffer.size() > m_rxCmdLength)
			m_rxCmdBuffer.resize(m_rxCmdLength);

		// process the message and then clear the buffer
		processRawMessage(m_rxCmdBuffer);
		m_rxCmdBuffer.clear();
	}
}

// -----------------------------------------------------------------------------
/*!
	\internal

	Called when we have reassembled a complete message from one or more
	individual hid report notifications.

 */
void RciMessageTunnelAndroid::processRawMessage(const QByteArray &message)
{
	// qDebug() << "message = " << arrayToHex(message);

	const quint8 *messagePtr = reinterpret_cast<const quint8*>(message.data());
	int messageLen = message.length();


	//    byte 0  :  bit 7      : ?
	//    byte 0  :  bits 6:5   : type (0=cmd, err=1, ack=2, nak=3)
	//    byte 0  :  bit 4      : flag (1=crc)
	//    byte 0  :  bits 3:2   : ?
	//    byte 0  :  bits 1:0   : data length bits 9 and 8
	//    byte 1  :  bits 7:0   : data length bits 7 to 0  (length includes
	//                            3 byte header and 2 byte crc if set)
	//    byte 2  :  bits 7:0   : command
	//     ...    :             : data
	// byte 2 + n :             : crc-16 ccitt if crc flag is set


	// sanity check the minimum size
	if (Q_UNLIKELY(!messagePtr || (messageLen < 3))) {
		qWarning("message to short at %d bytes, discarding", messageLen);
		return;
	}


	// the length should have already been checked before getting to this point
	// so no need to check again

	// if the crc flag is set then perform a crc16 check over the data
	if (messagePtr[0] & 0x10) {

		// sanity check we have the crc bytes
		if (messageLen < 5) {
			qWarning("message to short at %d bytes to contain crc", messageLen);
			return;
		}

		// get the crc sent and then trim off the data
		const quint16 actualCrc = (quint16(messagePtr[messageLen - 1]) << 8) |
		                          (quint16(messagePtr[messageLen - 2]) << 0);

		// calulate the crc and compare
		const quint16 expectCrc = calculateCrc(messagePtr, (messageLen - 2));

		if (expectCrc != actualCrc) {
			qWarning("invalid crc (expected=0x%04x, actual=0x%04x)",
			         expectCrc, actualCrc);
			return;
		}

		// shrink the packet length to trim of the crc
		messageLen -= 2;
	}

	// get the type
	RciMessageType type = RciMessageType::Unknown;
	switch ((messagePtr[0] >> 5) & 0x3) {
		case 0x0:
			type = RciMessageType::Command;
			break;
		case 0x1:
			type = RciMessageType::Error;
			break;
		case 0x2:
			type = RciMessageType::Ack;
			break;
		case 0x3:
			type = RciMessageType::Nak;
			break;
	}

	// get the command and sanity check it's one of the known ones
	RciMessageCommand command;
	switch (RciMessageCommand(messagePtr[2])) {
		case RciMessageCommand::GetProtocolVersion:
		case RciMessageCommand::CloneProtection:
		case RciMessageCommand::GetManufacturerName:
		case RciMessageCommand::GetModelNumber:
		case RciMessageCommand::GetSerialNumber:
		case RciMessageCommand::GetHardwareRevision:
		case RciMessageCommand::GetFirmwareVersion:
		case RciMessageCommand::GetSoftwareVersion:
		case RciMessageCommand::GetSystemId:
		case RciMessageCommand::GetPnPId:
		case RciMessageCommand::GetAllRevisions:
		case RciMessageCommand::GetDeviceName:
		case RciMessageCommand::GetBatteryLevel:
		case RciMessageCommand::RegisterBatteryLevel:
		case RciMessageCommand::GetRssi:
		case RciMessageCommand::SetAlert:
		case RciMessageCommand::GetAlert:
		case RciMessageCommand::SetAudioStatus:
		case RciMessageCommand::GetAudioStatus:
		case RciMessageCommand::SetTouchStatus:
		case RciMessageCommand::GetTouchStatus:
		case RciMessageCommand::SendIrCode:
		case RciMessageCommand::SetIrSignal:
		case RciMessageCommand::GetIrSignal:
		case RciMessageCommand::SetConfig:
		case RciMessageCommand::GetConfig:
		case RciMessageCommand::DisableIrSignal:
		case RciMessageCommand::EnableIrSignal:
		case RciMessageCommand::StartUpdate:
		case RciMessageCommand::FinishUpdate:
		case RciMessageCommand::PrepareArchive:
		case RciMessageCommand::UploadArchive:
		case RciMessageCommand::FinishArchive:
		case RciMessageCommand::GetDebugDiag:
			command = static_cast<RciMessageCommand>(messagePtr[2]);
			break;
		default:
			qWarning("message has unknown command (0x%02x)", messagePtr[2]);
			return;
	}


	// get the data
	const QByteArray data(reinterpret_cast<const char*>(messagePtr + 3),
	                      (messageLen - 3));

	// debugging
	qDebug() << "received message: type =" << type
	         << ", command =" << command
	         << ", data = " << arrayToHex(data);

	//
	onRecvMessage(type, command, data);
}

// -----------------------------------------------------------------------------
/*!
	\internal

	Called a complete verified (crc checked) message has arrived and been
	decoded.  This checks if the received message matches what was in the
	request queue and if so triggers the reply's finished signals.

 */
void RciMessageTunnelAndroid::onRecvMessage(RciMessageType type,
                                            RciMessageCommand command,
                                            const QByteArray &data)
{
	// if the message is an unsolicited command (i.e. battery level changed)
	// then just emit the signal with the command data
	if (type == RciMessageType::Command) {

		emit commandReceived(command, data);


	// else the message is an nak, ack or error type and therefore we should
	// have a pending command
	} else {

		// check if we're expecting a reply to this command
		QMap<RciMessageCommand, Request>::iterator it =
			m_outstandingRequests.find(command);
		if (Q_UNLIKELY(it == m_outstandingRequests.end())) {
			qWarning() << "received a reply to command" << command
			           << "but that doesn't match any outstanding requests";
			return;
		}
/*
		// check the request queue has something in it
		if (Q_UNLIKELY(m_requests.isEmpty())) {
			qWarning() << "received an reply to command" << command
			           << "but have no outstanding requests";
			return;
		}

		// check that the pending reply matches the command received
		const Request &request = m_requests.head();
		if (Q_UNLIKELY(request.command != command)) {
			qWarning() << "received a reply to command" << command
			           << "but that doesn't match the pending command"
			           << request.command;

			// NB: we don't free the pending reply object here, instead we
			// let the timeout clean-up.  We may need to re-visit this logic
			// in the future if we have issues here.
			return;
		}
*/

		// take a temporary copy of the pending reply and then clear the
		// one stored, this is so that clients can try sending another request
		// in the handlers for the signals below
		QSharedPointer<RciMessageReplyImpl> reply = it.value().reply;
		m_outstandingRequests.erase(it);

		// stop the timeout timer now we have a reply
//		m_timeoutTimer.stop();


		// populate the reply object with the response
		if (type == RciMessageType::Error) {

			// on an error the first byte after the header should contain
			// the error code
			if (data.length() >= 1)
				reply->setError(RciMessageError(data[0]));
			else
				reply->setError(RciMessageError::UnknownError);

		} else {

			// the reply is an ack or nak
			reply->setData(data);
		}

		reply->setType(type);

		// emit the signals from both the reply object and ourselves
		reply->emitFinished();
		emit finished(reply);
	}
}

// -----------------------------------------------------------------------------
/*!
	\internal

	Called when the timeout timer fires after we're sent off a request. If
	we have a pending request then we complete that request with a 'timed out'
	error code if it's retries count is less than or equal to zero.

 */
void RciMessageTunnelAndroid::onTimeout(quint64 requestId)
{
	// check if the request is still outstanding, usually it's not and therefore
	// we can just ignore this event ... unfortunately there is no API for
	// cancelling singleshot timers so a timeout timer always fires even for the
	// happy case.
	QMap<RciMessageCommand, Request>::iterator it = m_outstandingRequests.begin();
	for (; it != m_outstandingRequests.end(); ++it) {
		const Request &request = it.value();
		if (request.id == requestId)
			break;
	}

	if (Q_LIKELY(it == m_outstandingRequests.end()))
		return;


	// get the request object
	Request &request = it.value();

	// check if the retry count has been exhausted
	if (request.retries <= 0) {

		// get the reply object and then erase from the outstanding request map
		QSharedPointer<RciMessageReplyImpl> reply = request.reply;
		m_outstandingRequests.erase(it);

		// mark the pending request as a timeout error
		reply->setType(RciMessageType::Error);
		reply->setError(RciMessageError::TimedOut);

		// emit the signals from both the reply object and ourselves
		reply->emitFinished();
		emit finished(reply);

	} else {

		// decrement the retries
		request.retries--;

		// get a handle to the reply object
		QSharedPointer<RciMessageReplyImpl> reply = request.reply;

		// attempt to send another request
		if (sendRequest(reply->request()) == false) {

			// remove from the outstanding request map
			m_outstandingRequests.erase(it);

			// set the reply error
			reply->setType(RciMessageType::Error);
			reply->setError(RciMessageError::UnknownError);

			// emit the signals that the request has finished (albeit with an
			// error)
			reply->emitFinished();
			emit finished(reply);

		} else {

			// create another single-shot timer for the timeout, it's attached
			// to a functor so we can add the request id to the timer callback
			std::function<void()> functor = std::bind(&RciMessageTunnelAndroid::onTimeout,
			                                          this, request.id);

			QTimer::singleShot(request.timeout, this, functor);
		}
	}

}

// -----------------------------------------------------------------------------
/*!
	\internal

	Aborts all queued requests and outstanding replies.

 */
void RciMessageTunnelAndroid::abortAll()
{
	// cancel all outstanding requests
	QMap<RciMessageCommand, Request>::iterator it = m_outstandingRequests.begin();
	while (it != m_outstandingRequests.end()) {

		// get and clear the reply object
		QSharedPointer<RciMessageReplyImpl> reply = it.value().reply;
		it = m_outstandingRequests.erase(it);

		// mark the pending request as a timeout error
		reply->setType(RciMessageType::Error);
		reply->setError(RciMessageError::TunnelClosed);

		// emit the signals from both the reply object and ourselves
		reply->emitFinished();
		emit finished(reply);
	}

}

