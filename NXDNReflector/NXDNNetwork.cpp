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

#include "NXDNNetwork.h"
#include "Utils.h"
#include "Log.h"

#include <cstdio>
#include <cassert>
#include <cstring>

CNXDNNetwork::CNXDNNetwork(unsigned int port, bool debug) :
m_socket(port),
m_debug(debug)
{
}

CNXDNNetwork::~CNXDNNetwork()
{
}

bool CNXDNNetwork::open()
{
	LogInfo("Opening NXDN network connection");

	return m_socket.open();
}

bool CNXDNNetwork::write(const unsigned char* data, unsigned int length, const sockaddr_storage& addr, unsigned int addrLen)
{
	assert(data != NULL);
	assert(length > 0U);

	if (m_debug)
		CUtils::dump(1U, "NXDN Network Data Sent", data, length);

	return m_socket.write(data, length, addr, addrLen);
}

bool CNXDNNetwork::write(const unsigned char* data, unsigned int length, unsigned short srcId, unsigned short dstId, bool grp, const sockaddr_storage& addr, unsigned int addrLen)
{
	assert(data != NULL);
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
		// This if data.
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

	return m_socket.write(buffer, 43U, addr, addrLen);
}

unsigned int CNXDNNetwork::read(unsigned char* data, unsigned int length, sockaddr_storage& addr, unsigned int& addrLen)
{
	assert(data != NULL);
	assert(length > 0U);

	int len = m_socket.read(data, length, addr, addrLen);
	if (len <= 0)
		return 0U;

	// Invalid packet type?
	if (::memcmp(data, "NXDN", 4U) != 0)
		return 0U;

	if (len != 17 && len != 43)
		return 0U;

	if (m_debug)
		CUtils::dump(1U, "NXDN Network Data Received", data, len);

	return len;
}

void CNXDNNetwork::close()
{
	m_socket.close();

	LogInfo("Closing NXDN network connection");
}
