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

#include "IcomNetwork.h"
#include "Utils.h"
#include "Log.h"

#include <cstdio>
#include <cassert>
#include <cstring>

const unsigned int BUFFER_LENGTH = 200U;

CIcomNetwork::CIcomNetwork(const std::string& localAddress, unsigned int localPort, const std::string& gatewayAddress, unsigned int gatewayPort, bool debug) :
m_socket(localAddress, localPort),
m_address(),
m_port(gatewayPort),
m_debug(debug),
m_buffer(1000U, "Icom")
{
	assert(gatewayPort > 0U);
	assert(!gatewayAddress.empty());

	m_address = CUDPSocket::lookup(gatewayAddress);
}

CIcomNetwork::~CIcomNetwork()
{
}

bool CIcomNetwork::open()
{
	LogMessage("Opening Icom connection");

	if (m_address.s_addr == INADDR_NONE)
		return false;

	return m_socket.open();
}

bool CIcomNetwork::write(const unsigned char* data, unsigned int length)
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
	buffer[38U] = (data[0U] == 0x81U || data[0U] == 0x83U) ? 0x1CU : 0x10U;
	buffer[39U] = 0x21U;

	::memcpy(buffer + 40U, data, length);

	if (m_debug)
		CUtils::dump(1U, "Icom Data Sent", buffer, 102U);

	return m_socket.write(buffer, 102U, m_address, m_port);
}

void CIcomNetwork::clock(unsigned int ms)
{
	unsigned char buffer[BUFFER_LENGTH];

	in_addr address;
	unsigned int port;
	int length = m_socket.read(buffer, BUFFER_LENGTH, address, port);
	if (length <= 0)
		return;

	// Invalid packet type?
	if (::memcmp(buffer, "ICOM", 4U) != 0)
		return;

	// Check if the data is for us
	if (m_address.s_addr != address.s_addr || port != m_port) {
		LogMessage("Icom packet received from an invalid source, %08X != %08X and/or %u != %u", m_address.s_addr, address.s_addr, m_port, port);
		return;
	}

	// An Icom repeater connect request
	if (buffer[4U] == 0x01U && buffer[5U] == 0x61U) {
		buffer[5U]  = 0x62U;
		buffer[37U] = 0x02U;
		buffer[38U] = 0x4FU;
		buffer[39U] = 0x4BU;
		m_socket.write(buffer, length, m_address, m_port);
		return;
	}

	if (length != 102)
		return;

	if (m_debug)
		CUtils::dump(1U, "Icom Data Received", buffer, length);

	m_buffer.addData(buffer + 40U, 33U);
}

bool CIcomNetwork::read(unsigned char* data)
{
	assert(data != NULL);

	if (m_buffer.isEmpty())
		return false;

	m_buffer.getData(data, 33U);

	return true;
}

void CIcomNetwork::close()
{
	m_socket.close();

	LogMessage("Closing Icom connection");
}
