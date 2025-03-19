/*
 *   Copyright (C) 2009-2014,2016,2018,2020,2024,2025 by Jonathan Naylor G4KLX
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

#include "NXDNNetwork.h"
#include "Utils.h"
#include "Log.h"

#include <cstdio>
#include <cassert>
#include <cstring>

CNXDNNetwork::CNXDNNetwork(unsigned short port, const std::string& callsign, bool debug) :
m_callsign(callsign),
m_socket4(port),
m_socket6(port),
m_debug(debug)
{
	assert(port > 0U);

	m_callsign.resize(10U, ' ');
}

CNXDNNetwork::~CNXDNNetwork()
{
}

bool CNXDNNetwork::open()
{
	LogInfo("Opening NXDN network connection");

	sockaddr_storage addr4;
	addr4.ss_family = AF_INET;

	bool ret = m_socket4.open(addr4);
	if (!ret)
		return false;

	sockaddr_storage addr6;
	addr6.ss_family = AF_INET6;

	return m_socket6.open(addr6);
}

bool CNXDNNetwork::writeData(const unsigned char* data, unsigned int length, unsigned short srcId, unsigned short dstId, bool grp, const sockaddr_storage& addr, unsigned int addrLen)
{
	assert(data != nullptr);
	assert(length > 0U);

	unsigned char buffer[50U];

	buffer[0U] = 'N';
	buffer[1U] = 'X';
	buffer[2U] = 'D';
	buffer[3U] = 'N';
	buffer[4U] = 'D';

	buffer[5U] = (srcId >> 8) & 0xFFU;
	buffer[6U] = (srcId >> 0) & 0xFFU;

	buffer[7U] = (dstId >> 8) & 0xFFU;
	buffer[8U] = (dstId >> 0) & 0xFFU;

	buffer[9U] = 0x00U;
	buffer[9U] |= grp ? 0x01U : 0x00U;

	if (data[0U] == 0x81U || data[0U] == 0x83U) {
		// This is a voice header or trailer.
		buffer[9U] |= data[5U] == 0x01U ? 0x04U : 0x00U;
		buffer[9U] |= data[5U] == 0x08U ? 0x08U : 0x00U;
	} else if ((data[0U] & 0xF0U) == 0x90U) {
		// This is data.
		buffer[9U] |= 0x02U;
		if (data[0U] == 0x90U || data[0U] == 0x92U || data[0U] == 0x9CU || data[0U] == 0x9EU) {
			// This is data header or trailer.
			buffer[9U] |= data[2U] == 0x09U ? 0x04U : 0x00U;
			buffer[9U] |= data[2U] == 0x08U ? 0x08U : 0x00U;
		}
	}

	::memcpy(buffer + 10U, data, 33U);

	if (m_debug)
		CUtils::dump(1U, "NXDN Network Data Sent", buffer, 43U);

	switch (addr.ss_family) {
		case AF_INET:
			return m_socket4.write(buffer, 43U, addr, addrLen);
		case AF_INET6:
			return m_socket6.write(buffer, 43U, addr, addrLen);
		default:
			LogError("Unknown socket address family - %u", addr.ss_family);
			return false;
	}
}

bool CNXDNNetwork::writePoll(const sockaddr_storage& addr, unsigned int addrLen, unsigned short tg)
{
	unsigned char data[20U];

	data[0U] = 'N';
	data[1U] = 'X';
	data[2U] = 'D';
	data[3U] = 'N';
	data[4U] = 'P';

	for (unsigned int i = 0U; i < 10U; i++)
		data[i + 5U] = m_callsign.at(i);

	data[15U] = (tg >> 8) & 0xFFU;
	data[16U] = (tg >> 0) & 0xFFU;

	if (m_debug)
		CUtils::dump(1U, "NXDN Network Poll Sent", data, 17U);

	switch (addr.ss_family) {
		case AF_INET:
			return m_socket4.write(data, 17U, addr, addrLen);
		case AF_INET6:
			return m_socket6.write(data, 17U, addr, addrLen);
		default:
			LogError("Unknown socket address family - %u", addr.ss_family);
			return false;
	}
}

bool CNXDNNetwork::writeUnlink(const sockaddr_storage& addr, unsigned int addrLen, unsigned short tg)
{
	unsigned char data[20U];

	data[0U] = 'N';
	data[1U] = 'X';
	data[2U] = 'D';
	data[3U] = 'N';
	data[4U] = 'U';

	for (unsigned int i = 0U; i < 10U; i++)
		data[i + 5U] = m_callsign.at(i);

	data[15U] = (tg >> 8) & 0xFFU;
	data[16U] = (tg >> 0) & 0xFFU;

	if (m_debug)
		CUtils::dump(1U, "NXDN Network Unlink Sent", data, 17U);

	switch (addr.ss_family) {
		case AF_INET:
			return m_socket4.write(data, 17U, addr, addrLen);
		case AF_INET6:
			return m_socket6.write(data, 17U, addr, addrLen);
		default:
			LogError("Unknown socket address family - %u", addr.ss_family);
			return false;
	}
}

unsigned int CNXDNNetwork::readData(unsigned char* data, unsigned int length, sockaddr_storage& addr, unsigned int& addrLen)
{
	assert(data != nullptr);
	assert(length > 0U);

	int len = m_socket4.read(data, length, addr, addrLen);
	if (len <= 0)
		len = m_socket6.read(data, length, addr, addrLen);
	if (len <= 0)
		return 0U;

	if ((::memcmp(data, "NXDNP", 5U) == 0 && len == 17) || (::memcmp(data, "NXDND", 5U) == 0 && len == 43)) {
		if (m_debug)
			CUtils::dump(1U, "NXDN Network Data Received", data, len);

		return len;
	}

	return 0U;
}

void CNXDNNetwork::close()
{
	m_socket4.close();
	m_socket6.close();

	LogInfo("Closing NXDN network connection");
}
