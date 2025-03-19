/*
 *   Copyright (C) 2009-2014,2016,2018,2020,2025 by Jonathan Naylor G4KLX
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

CIcomNetwork::CIcomNetwork(unsigned short localPort, const std::string& rptAddress, unsigned short rptPort, bool debug) :
m_socket(localPort),
m_addr(),
m_addrLen(0U),
m_debug(debug)
{
	assert(localPort > 0U);
	assert(!rptAddress.empty());
	assert(rptPort > 0U);

	if (CUDPSocket::lookup(rptAddress, rptPort, m_addr, m_addrLen) != 0)
		m_addrLen = 0U;
}

CIcomNetwork::~CIcomNetwork()
{
}

bool CIcomNetwork::open()
{
	if (m_addrLen == 0U) {
		LogError("Unable to resolve the address of the Icom network");
		return false;
	}

	LogMessage("Opening Icom connection");

	return m_socket.open(m_addr);
}

bool CIcomNetwork::write(const unsigned char* data, unsigned int length)
{
	assert(data != nullptr);

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

	if ((data[0U] & 0xF0U) == 0x90U) {
		buffer[37U] = 0x23U;
		buffer[38U] = 0x02U;
		buffer[39U] = 0x18U;
	} else {
		buffer[37U] = 0x23U;
		buffer[38U] = (data[0U] == 0x81U || data[0U] == 0x83U) ? 0x1CU : 0x10U;
		buffer[39U] = 0x21U;
	}

	::memcpy(buffer + 40U, data, length);

	if (m_debug)
		CUtils::dump(1U, "Icom Data Sent", buffer, 102U);

	return m_socket.write(buffer, 102U, m_addr, m_addrLen);
}

unsigned int CIcomNetwork::read(unsigned char* data)
{
	assert(data != nullptr);

	unsigned char buffer[BUFFER_LENGTH];
	sockaddr_storage addr;
	unsigned int addrlen;

	int length = m_socket.read(buffer, BUFFER_LENGTH, addr, addrlen);
	if (length <= 0)
		return 0U;

	if (!CUDPSocket::match(m_addr, addr, IPMATCHTYPE::ADDRESS_ONLY)) {
		LogWarning("Icom Data received from an unknown address");
		return 0U;
	}

	// Invalid packet type?
	if (::memcmp(buffer, "ICOM", 4U) != 0)
		return 0U;

	// An Icom repeater connect request
	if (buffer[4U] == 0x01U && buffer[5U] == 0x61U) {
		buffer[5U]  = 0x62U;
		buffer[37U] = 0x02U;
		buffer[38U] = 0x4FU;
		buffer[39U] = 0x4BU;
		m_socket.write(buffer, length, addr, addrlen);
		return 0U;
	}

	if (length != 102)
		return 0U;

	if (m_debug)
		CUtils::dump(1U, "Icom Data Received", buffer, length);

	::memcpy(data, buffer + 40U, 33U);

	return 33U;
}

void CIcomNetwork::close()
{
	m_socket.close();

	LogMessage("Closing Icom connection");
}

void CIcomNetwork::clock(unsigned int ms)
{
}
