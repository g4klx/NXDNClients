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

#include "NXCoreNetwork.h"
#include "Utils.h"
#include "Log.h"

#include <cstdio>
#include <cassert>
#include <cstring>

const unsigned int BUFFER_LENGTH = 200U;

const unsigned int NXCORE_PORT = 41300U;

CNXCoreNetwork::CNXCoreNetwork(const std::string& address, bool debug) :
m_socket(NXCORE_PORT),
m_address(),
m_debug(debug)
{
	assert(!address.empty());

	m_address = CUDPSocket::lookup(address);
}

CNXCoreNetwork::~CNXCoreNetwork()
{
}

bool CNXCoreNetwork::open()
{
	LogMessage("Opening NXCore network connection");

	if (m_address.s_addr == INADDR_NONE)
		return false;

	return m_socket.open();
}

bool CNXCoreNetwork::write(const unsigned char* data, unsigned int len)
{
	assert(data != NULL);

	unsigned char buffer[110U];
	::memset(buffer, 0x00U, 110U);

	buffer[0U] = 'I';
	buffer[1U] = 'C';
	buffer[2U] = 'O';
	buffer[3U] = 'M';
	buffer[4U] = 0x01U;
	buffer[5U] = 0x01U;
	buffer[6U] = 0x08U;
	buffer[7U] = 0xE0U;

	buffer[37U] = 0x23U;
	buffer[38U] = (data[9U] & 0x0CU) != 0x00U ? 0x1CU : 0x10U;
	buffer[39U] = 0x21U;

	::memcpy(buffer + 40U, data + 10U, 33U);

	if (m_debug)
		CUtils::dump(1U, "NXCore Network Data Sent", buffer, 102U);

	return m_socket.write(buffer, 102U, m_address, NXCORE_PORT);
}

unsigned int CNXCoreNetwork::read(unsigned char* data, unsigned int len)
{
	unsigned char buffer[BUFFER_LENGTH];

	in_addr address;
	unsigned int port;
	int length = m_socket.read(data, BUFFER_LENGTH, address, port);
	if (length <= 0)
		return 0U;

	// Check if the data is for us
	if (m_address.s_addr != address.s_addr || port != NXCORE_PORT) {
		LogMessage("NXCore packet received from an invalid source, %08X != %08X and/or %u != %u", m_address.s_addr, address.s_addr, NXCORE_PORT, port);
		return 0U;
	}

	// Invalid packet type?
	if (::memcmp(buffer, "ICOM", 4U) != 0)
		return 0U;

	if (length != 102)
		return 0U;

	if (m_debug)
		CUtils::dump(1U, "NXCore Network Data Received", buffer, length);

	::memcpy(data, buffer + 40U, 33U);

	return 33U;
}

void CNXCoreNetwork::close()
{
	m_socket.close();

	LogMessage("Closing NXCore network connection");
}
