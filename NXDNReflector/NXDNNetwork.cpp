/*
 *   Copyright (C) 2009-2014,2016,2018 by Jonathan Naylor G4KLX
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

bool CNXDNNetwork::write(const unsigned char* data, unsigned int length, const in_addr& address, unsigned int port)
{
	assert(data != NULL);
	assert(length > 0U);
	assert(port > 0U);

	if (m_debug)
		CUtils::dump(1U, "NXDN Network Data Sent", data, length);

	return m_socket.write(data, length, address, port);
}

bool CNXDNNetwork::write(const unsigned char* data, unsigned int length, unsigned short srcId, unsigned short dstId, bool grp, const in_addr& address, unsigned int port)
{
	assert(data != NULL);
	assert(length > 0U);
	assert(port > 0U);

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
		buffer[9U] |= data[5U] == 0x01U ? 0x04U : 0x00U;
		buffer[9U] |= data[5U] == 0x08U ? 0x08U : 0x00U;
	}

	::memcpy(buffer + 10U, data, 33U);

	if (m_debug)
		CUtils::dump(1U, "NXDN Network Data Sent", buffer, 43U);

	return m_socket.write(buffer, 43U, address, port);
}

unsigned int CNXDNNetwork::read(unsigned char* data, unsigned int length, in_addr& address, unsigned int& port)
{
	assert(data != NULL);
	assert(length > 0U);

	int len = m_socket.read(data, length, address, port);
	if (len <= 0)
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
