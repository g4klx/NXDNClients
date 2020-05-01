/*
 *   Copyright (C) 2009-2014,2016,2018,2020 by Jonathan Naylor G4KLX
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "KenwoodNetwork.h"
#include "NXDNCRC.h"
#include "Utils.h"
#include "Log.h"

#include <cstdio>
#include <cassert>
#include <cstring>

const unsigned char BIT_MASK_TABLE[] = { 0x80U, 0x40U, 0x20U, 0x10U, 0x08U, 0x04U, 0x02U, 0x01U };

#define WRITE_BIT(p,i,b) p[(i)>>3] = (b) ? (p[(i)>>3] | BIT_MASK_TABLE[(i)&7]) : (p[(i)>>3] & ~BIT_MASK_TABLE[(i)&7])
#define READ_BIT(p,i)    (p[(i)>>3] & BIT_MASK_TABLE[(i)&7])

const unsigned int BUFFER_LENGTH = 200U;

CKenwoodNetwork::CKenwoodNetwork(unsigned int localPort, const std::string& rptAddress, unsigned int rptPort, bool debug) :
m_rtcpSocket(localPort + 1U),
m_rtpSocket(localPort + 0U),
m_stopWatch(),
m_address(),
m_rtcpPort(rptPort + 1U),
m_rtpPort(rptPort + 0U),
m_seqNo(0U),
m_timeStamp(0U),
m_ssrc(0U),
m_debug(debug),
m_timer(1000U, 0U, 200U)
{
	assert(localPort > 0U);
	assert(!rptAddress.empty());
	assert(rptPort > 0U);

	m_address = CUDPSocket::lookup(rptAddress);

	::srand((unsigned int)m_stopWatch.time());
}

CKenwoodNetwork::~CKenwoodNetwork()
{
}

bool CKenwoodNetwork::open()
{
	LogMessage("Opening Kenwood connection");

	if (m_address.s_addr == INADDR_NONE)
		return false;

	if (!m_rtcpSocket.open())
		return false;

	if (!m_rtpSocket.open()) {
		m_rtcpSocket.close();
		return false;
	}

	m_ssrc = ::rand();

	return true;
}

bool CKenwoodNetwork::write(const unsigned char* data, unsigned int length)
{
	assert(data != NULL);

	switch (data[0U]) {
	case 0x81U:	// Voice header or trailer
	case 0x83U:
		return processIcomVoiceHeader(data);
	case 0xACU:	// Voice data
	case 0xAEU:
		return processIcomVoiceData(data);
	default:
		return false;
	}
}

bool CKenwoodNetwork::processIcomVoiceHeader(const unsigned char* inData)
{
	assert(inData != NULL);

	unsigned char outData[30U];
	::memset(outData, 0x00U, 30U);

	// SACCH
	outData[0U] = inData[2U];
	outData[1U] = inData[1U];
	outData[2U] = inData[4U] & 0xC0U;
	outData[3U] = inData[3U];

	// FACCH 1+2
	outData[4U] = outData[14U] = inData[6U];
	outData[5U] = outData[15U] = inData[5U];
	outData[6U] = outData[16U] = inData[8U];
	outData[7U] = outData[17U] = inData[7U];
	outData[8U] = outData[18U] = inData[10U];
	outData[9U] = outData[19U] = inData[9U];
	outData[10U] = outData[20U] = inData[12U];
	outData[11U] = outData[21U] = inData[11U];

	unsigned short src = (inData[8U] << 8) + (inData[9U] << 0);
	unsigned short dst = (inData[10U] << 8) + (inData[11U] << 0);
	unsigned char type = (inData[7U] >> 5) & 0x07U;

	switch (inData[5U] & 0x3FU) {
	case 0x01U:
		m_timer.start();
		writeRTCPData(type, src, dst);
		return writeRTPVoiceHeader(outData);
	case 0x08U:
		m_timer.stop();
		writeRTCPData(type, src, dst);
		return writeRTPVoiceTrailer(outData);
	default:
		return false;
	}
}

bool CKenwoodNetwork::processIcomVoiceData(const unsigned char* inData)
{
	assert(inData != NULL);

	unsigned char outData[40U], temp[10U];
	::memset(outData, 0x00U, 40U);

	// SACCH
	outData[0U] = inData[2U];
	outData[1U] = inData[1U];
	outData[2U] = inData[4U] & 0xC0U;
	outData[3U] = inData[3U];

	// Audio 1
	::memset(temp, 0x00U, 10U);
	for (unsigned int i = 0U; i < 49U; i++) {
		unsigned int offset = (5U * 8U) + i;
		bool b = READ_BIT(inData, offset);
		WRITE_BIT(temp, i, b);
	}
	outData[4U] = temp[1U];
	outData[5U] = temp[0U];
	outData[6U] = temp[3U];
	outData[7U] = temp[2U];
	outData[8U] = temp[5U];
	outData[9U] = temp[4U];
	outData[10U] = temp[7U];
	outData[11U] = temp[6U];

	// Audio 2
	::memset(temp, 0x00U, 10U);
	for (unsigned int i = 0U; i < 49U; i++) {
		unsigned int offset = (5U * 8U) + 49U + i;
		bool b = READ_BIT(inData, offset);
		WRITE_BIT(temp, i, b);
	}
	outData[12U] = temp[1U];
	outData[13U] = temp[0U];
	outData[14U] = temp[3U];
	outData[15U] = temp[2U];
	outData[16U] = temp[5U];
	outData[17U] = temp[4U];
	outData[18U] = temp[7U];
	outData[19U] = temp[6U];

	// Audio 3
	::memset(temp, 0x00U, 10U);
	for (unsigned int i = 0U; i < 49U; i++) {
		unsigned int offset = (19U * 8U) + i;
		bool b = READ_BIT(inData, offset);
		WRITE_BIT(temp, i, b);
	}
	outData[20U] = temp[1U];
	outData[21U] = temp[0U];
	outData[22U] = temp[3U];
	outData[23U] = temp[2U];
	outData[24U] = temp[5U];
	outData[25U] = temp[4U];
	outData[26U] = temp[7U];
	outData[27U] = temp[6U];

	// Audio 4
	::memset(temp, 0x00U, 10U);
	for (unsigned int i = 0U; i < 49U; i++) {
		unsigned int offset = (19U * 8U) + 49U + i;
		bool b = READ_BIT(inData, offset);
		WRITE_BIT(temp, i, b);
	}
	outData[28U] = temp[1U];
	outData[29U] = temp[0U];
	outData[30U] = temp[3U];
	outData[31U] = temp[2U];
	outData[32U] = temp[5U];
	outData[33U] = temp[4U];
	outData[34U] = temp[7U];
	outData[35U] = temp[6U];

	return writeRTPVoiceData(outData);
}

bool CKenwoodNetwork::writeRTPVoiceHeader(const unsigned char* data)
{
	assert(data != NULL);

	unsigned char buffer[50U];
	::memset(buffer, 0x00U, 50U);

	buffer[0U] = 0x80U;
	buffer[1U] = 0x66U;

	buffer[2U] = (m_seqNo >> 8) & 0xFFU;
	buffer[3U] = (m_seqNo >> 0) & 0xFFU;
	m_seqNo++;

	m_timeStamp = (unsigned long)m_stopWatch.time();

	buffer[4U] = (m_timeStamp >> 24) & 0xFFU;
	buffer[5U] = (m_timeStamp >> 16) & 0xFFU;
	buffer[6U] = (m_timeStamp >> 8) & 0xFFU;
	buffer[7U] = (m_timeStamp >> 0) & 0xFFU;
	m_timeStamp += 640U;

	buffer[8U]  = (m_ssrc >> 24) & 0xFFU;
	buffer[9U]  = (m_ssrc >> 16) & 0xFFU;
	buffer[10U] = (m_ssrc >> 8) & 0xFFU;
	buffer[11U] = (m_ssrc >> 0) & 0xFFU;

	buffer[16U] = 0x03U;
	buffer[17U] = 0x03U;
	buffer[18U] = 0x04U;
	buffer[19U] = 0x04U;
	buffer[20U] = 0x0AU;
	buffer[21U] = 0x05U;
	buffer[22U] = 0x0AU;

	::memcpy(buffer + 23U, data, 24U);

	if (m_debug)
		CUtils::dump(1U, "Kenwood Network RTP Data Sent", buffer, 47U);

	return m_rtpSocket.write(buffer, 47U, m_address, m_rtpPort);
}

bool CKenwoodNetwork::writeRTPVoiceTrailer(const unsigned char* data)
{
	assert(data != NULL);

	unsigned char buffer[50U];
	::memset(buffer, 0x00U, 50U);

	buffer[0U] = 0x80U;
	buffer[1U] = 0x66U;

	buffer[2U] = (m_seqNo >> 8) & 0xFFU;
	buffer[3U] = (m_seqNo >> 0) & 0xFFU;

	buffer[4U] = (m_timeStamp >> 24) & 0xFFU;
	buffer[5U] = (m_timeStamp >> 16) & 0xFFU;
	buffer[6U] = (m_timeStamp >> 8) & 0xFFU;
	buffer[7U] = (m_timeStamp >> 0) & 0xFFU;

	buffer[8U]  = (m_ssrc >> 24) & 0xFFU;
	buffer[9U]  = (m_ssrc >> 16) & 0xFFU;
	buffer[10U] = (m_ssrc >> 8) & 0xFFU;
	buffer[11U] = (m_ssrc >> 0) & 0xFFU;

	buffer[16U] = 0x03U;
	buffer[17U] = 0x03U;
	buffer[18U] = 0x04U;
	buffer[19U] = 0x04U;
	buffer[20U] = 0x0AU;
	buffer[21U] = 0x05U;
	buffer[22U] = 0x0AU;

	::memcpy(buffer + 23U, data, 24U);

	if (m_debug)
		CUtils::dump(1U, "Kenwood Network RTP Data Sent", buffer, 47U);

	return m_rtpSocket.write(buffer, 47U, m_address, m_rtpPort);
}

bool CKenwoodNetwork::writeRTPVoiceData(const unsigned char* data)
{
	assert(data != NULL);

	unsigned char buffer[60U];
	::memset(buffer, 0x00U, 60U);

	buffer[0U] = 0x80U;
	buffer[1U] = 0x66U;

	buffer[2U] = (m_seqNo >> 8) & 0xFFU;
	buffer[3U] = (m_seqNo >> 0) & 0xFFU;
	m_seqNo++;

	buffer[4U] = (m_timeStamp >> 24) & 0xFFU;
	buffer[5U] = (m_timeStamp >> 16) & 0xFFU;
	buffer[6U] = (m_timeStamp >> 8) & 0xFFU;
	buffer[7U] = (m_timeStamp >> 0) & 0xFFU;
	m_timeStamp += 640U;

	buffer[8U]  = (m_ssrc >> 24) & 0xFFU;
	buffer[9U]  = (m_ssrc >> 16) & 0xFFU;
	buffer[10U] = (m_ssrc >> 8) & 0xFFU;
	buffer[11U] = (m_ssrc >> 0) & 0xFFU;

	buffer[16U] = 0x03U;
	buffer[17U] = 0x02U;
	buffer[18U] = 0x04U;
	buffer[19U] = 0x07U;
	buffer[20U] = 0x10U;
	buffer[21U] = 0x08U;
	buffer[22U] = 0x10U;

	::memcpy(buffer + 23U, data, 36U);

	if (m_debug)
		CUtils::dump(1U, "Kenwood Network RTP Data Sent", buffer, 59U);

	return m_rtpSocket.write(buffer, 59U, m_address, m_rtpPort);
}

bool CKenwoodNetwork::writeRTCPPing()
{
	unsigned char buffer[30U];
	::memset(buffer, 0x00U, 30U);

	buffer[0U] = 0x8AU;
	buffer[1U] = 0xCCU;

	buffer[3U] = 0x06U;

	buffer[4U] = (m_ssrc >> 24) & 0xFFU;
	buffer[5U] = (m_ssrc >> 16) & 0xFFU;
	buffer[6U] = (m_ssrc >> 8) & 0xFFU;
	buffer[7U] = (m_ssrc >> 0) & 0xFFU;

	buffer[8U]  = 'K';
	buffer[9U]  = 'W';
	buffer[10U] = 'N';
	buffer[11U] = 'E';

	buffer[22U] = 0x02U;

	buffer[24U] = 0x01U;
	buffer[25U] = 0x01U;

	if (m_debug)
		CUtils::dump(1U, "Kenwood Network RTCP Data Sent", buffer, 28U);

	return m_rtcpSocket.write(buffer, 28U, m_address, m_rtcpPort);
}

bool CKenwoodNetwork::writeRTCPData(unsigned char type, unsigned short src, unsigned short dst)
{
	unsigned char buffer[20U];
	::memset(buffer, 0x00U, 20U);

	buffer[0U] = 0x8BU;
	buffer[1U] = 0xCCU;

	buffer[3U] = 0x04U;

	buffer[4U] = (m_ssrc >> 24) & 0xFFU;
	buffer[5U] = (m_ssrc >> 16) & 0xFFU;
	buffer[6U] = (m_ssrc >> 8) & 0xFFU;
	buffer[7U] = (m_ssrc >> 0) & 0xFFU;

	buffer[8U]  = 'K';
	buffer[9U]  = 'W';
	buffer[10U] = 'N';
	buffer[11U] = 'E';

	buffer[12U] = (src >> 8) & 0xFFU;
	buffer[13U] = (src >> 0) & 0xFFU;

	buffer[14U] = (dst >> 8) & 0xFFU;
	buffer[15U] = (dst >> 0) & 0xFFU;

	buffer[16U] = type;

	if (m_debug)
		CUtils::dump(1U, "Kenwood Network RTCP Data Sent", buffer, 20U);

	return m_rtcpSocket.write(buffer, 20U, m_address, m_rtcpPort);
}

bool CKenwoodNetwork::read(unsigned char* data)
{
	assert(data != NULL);

	unsigned char dummy[BUFFER_LENGTH];
	readRTCP(dummy);

	unsigned int len = readRTP(data);
	switch (len) {
	case 0U:	// Nothing received
		return false;
	case 35U:	// Voice header or trailer
		return processKenwoodVoiceHeader(data);
	case 47U:	// Voice data
		processKenwoodVoiceData(data);
		return true;
	case 31U:	// Data
		processKenwoodData(data);
		return true;
	default:
		CUtils::dump(5U, "Unknown data received from the Kenwood network", data, len);
		return false;
	}
}

unsigned int CKenwoodNetwork::readRTP(unsigned char* data)
{
	assert(data != NULL);

	unsigned char buffer[BUFFER_LENGTH];

	in_addr address;
	unsigned int port;
	int length = m_rtpSocket.read(buffer, BUFFER_LENGTH, address, port);
	if (length <= 0)
		return 0U;

	// Check if the data is for us
	if (m_address.s_addr != address.s_addr) {
		LogMessage("Kenwood RTP packet received from an invalid source, %08X != %08X", m_address.s_addr, address.s_addr);
		return 0U;
	}

	if (m_debug)
		CUtils::dump(1U, "Kenwood Network RTP Data Received", buffer, length);

	::memcpy(data, buffer + 12U, length - 12U);

	return length - 12U;
}

unsigned int CKenwoodNetwork::readRTCP(unsigned char* data)
{
	assert(data != NULL);

	unsigned char buffer[BUFFER_LENGTH];

	in_addr address;
	unsigned int port;
	int length = m_rtcpSocket.read(buffer, BUFFER_LENGTH, address, port);
	if (length <= 0)
		return 0U;

	// Check if the data is for us
	if (m_address.s_addr != address.s_addr) {
		LogMessage("Kenwood RTCP packet received from an invalid source, %08X != %08X", m_address.s_addr, address.s_addr);
		return 0U;
	}

	if (m_debug)
		CUtils::dump(1U, "Kenwood Network RTCP Data Received", buffer, length);

	if (::memcmp(buffer + 8U, "KWNE", 4U) != 0) {
		LogError("Missing RTCP KWNE signature");
		return 0U;
	}

	::memcpy(data, buffer + 12U, length - 12U);

	return length - 12U;
}

void CKenwoodNetwork::close()
{
	m_rtcpSocket.close();
	m_rtpSocket.close();

	LogMessage("Closing Kenwood connection");
}

void CKenwoodNetwork::clock(unsigned int ms)
{
	m_timer.clock(ms);
	if (m_timer.isRunning() && m_timer.hasExpired()) {
		writeRTCPPing();
		m_timer.start();
	}
}

bool CKenwoodNetwork::processKenwoodVoiceHeader(unsigned char* inData)
{
	assert(inData != NULL);

	unsigned char outData[50U], temp[20U];
	::memset(outData, 0x00U, 50U);

	// LICH
	outData[0U] = 0x83U;

	// SACCH
	::memset(temp, 0x00U, 20U);
	temp[0U] = inData[12U];
	temp[1U] = inData[11U];
	temp[2U] = inData[14U];
	temp[3U] = inData[13U];
	CNXDNCRC::encodeCRC6(temp, 26U);
	::memcpy(outData + 1U, temp, 4U);

	// FACCH 1+2
	::memset(temp, 0x00U, 20U);
	temp[0U] = inData[16U];
	temp[1U] = inData[15U];
	temp[2U] = inData[18U];
	temp[3U] = inData[17U];
	temp[4U] = inData[20U];
	temp[5U] = inData[19U];
	temp[6U] = inData[22U];
	temp[7U] = inData[21U];
	temp[8U] = inData[24U];
	temp[9U] = inData[23U];
	CNXDNCRC::encodeCRC12(temp, 80U);
	::memcpy(outData + 5U, temp, 12U);
	::memcpy(outData + 19U, temp, 12U);

	switch (outData[5U] & 0x3FU) {
	case 0x01U:
		::memcpy(inData, outData, 33U);
		return true;
	case 0x08U:
		::memcpy(inData, outData, 33U);
		return true;
	default:
		return false;
	}
}

void CKenwoodNetwork::processKenwoodVoiceData(unsigned char* inData)
{
	assert(inData != NULL);

	unsigned char outData[50U], temp[20U];
	::memset(outData, 0x00U, 50U);

	// LICH
	outData[0U] = 0xAEU;

	// SACCH
	::memset(temp, 0x00U, 20U);
	temp[0U] = inData[12U];
	temp[1U] = inData[11U];
	temp[2U] = inData[14U];
	temp[3U] = inData[13U];
	CNXDNCRC::encodeCRC6(temp, 26U);
	::memcpy(outData + 1U, temp, 4U);

	// AMBE 1+2
	unsigned int n = 5U * 8U;

	temp[0U] = inData[16U];
	temp[1U] = inData[15U];
	temp[2U] = inData[18U];
	temp[3U] = inData[17U];
	temp[4U] = inData[20U];
	temp[5U] = inData[19U];
	temp[6U] = inData[22U];
	temp[7U] = inData[21U];

	for (unsigned int i = 0U; i < 49U; i++, n++) {
		bool b = READ_BIT(temp, i);
		WRITE_BIT(outData, n, b);
	}

	temp[0U] = inData[24U];
	temp[1U] = inData[23U];
	temp[2U] = inData[26U];
	temp[3U] = inData[25U];
	temp[4U] = inData[28U];
	temp[5U] = inData[27U];
	temp[6U] = inData[30U];
	temp[7U] = inData[29U];

	for (unsigned int i = 0U; i < 49U; i++, n++) {
		bool b = READ_BIT(temp, i);
		WRITE_BIT(outData, n, b);
	}

	// AMBE 3+4
	n = 19U * 8U;

	temp[0U] = inData[32U];
	temp[1U] = inData[31U];
	temp[2U] = inData[34U];
	temp[3U] = inData[33U];
	temp[4U] = inData[36U];
	temp[5U] = inData[35U];
	temp[6U] = inData[38U];
	temp[7U] = inData[37U];

	for (unsigned int i = 0U; i < 49U; i++, n++) {
		bool b = READ_BIT(temp, i);
		WRITE_BIT(outData, n, b);
	}

	temp[0U] = inData[40U];
	temp[1U] = inData[39U];
	temp[2U] = inData[42U];
	temp[3U] = inData[41U];
	temp[4U] = inData[44U];
	temp[5U] = inData[43U];
	temp[6U] = inData[46U];
	temp[7U] = inData[45U];

	for (unsigned int i = 0U; i < 49U; i++, n++) {
		bool b = READ_BIT(temp, i);
		WRITE_BIT(outData, n, b);
	}

	::memcpy(inData, outData, 33U);
}

void CKenwoodNetwork::processKenwoodData(unsigned char* inData)
{
	if (inData[7U] != 0x09U && inData[7U] != 0x0BU && inData[7U] != 0x08U)
		return;

	unsigned char outData[50U];

	if (inData[7U] == 0x09U || inData[7U] == 0x08U) {
		outData[0U] = 0x90U;
		outData[1U] = inData[8U];
		outData[2U] = inData[7U];
		outData[3U] = inData[10U];
		outData[4U] = inData[9U];
		outData[5U] = inData[12U];
		outData[6U] = inData[11U];
		::memcpy(inData, outData, 7U);
		CUtils::dump(4U, "Outgoing Kenwood GPS Data Header/Trailer", inData, 7U);
	} else {
		CUtils::dump(4U, "Incoming Kenwood GPS Data", inData, 31U);
		outData[0U]  = 0x90U;
		outData[1U]  = inData[8U];
		outData[2U]  = inData[7U];
		outData[3U]  = inData[10U];
		outData[4U]  = inData[9U];
		outData[5U]  = inData[12U];
		outData[6U]  = inData[11U];
		outData[7U]  = inData[14U];
		outData[8U]  = inData[13U];
		outData[9U]  = inData[16U];
		outData[10U] = inData[15U];
		outData[11U] = inData[18U];
		outData[12U] = inData[17U];
		outData[13U] = inData[20U];
		outData[14U] = inData[19U];
		outData[15U] = inData[22U];
		outData[16U] = inData[21U];
		outData[17U] = inData[24U];
		outData[18U] = inData[23U];
		outData[19U] = inData[26U];
		outData[20U] = inData[25U];
		outData[21U] = inData[28U];
		outData[22U] = inData[27U];
		outData[23U] = inData[29U];
		::memcpy(inData, outData, 24U);
		CUtils::dump(4U, "Outgoing Kenwood GPS Data Body", inData, 24U);
	}
}
