/*
 *   Copyright (C) 2009-2014,2016,2018,2020,2021 by Jonathan Naylor G4KLX
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

const unsigned int ICOM_PORT = 41300U;

CIcomNetwork::CIcomNetwork(const std::string& address, bool debug) :
m_socket(ICOM_PORT),
m_addr(),
m_addrLen(0U),
m_debug(debug)
{
	assert(!address.empty());

	if (CUDPSocket::lookup(address, ICOM_PORT, m_addr, m_addrLen) != 0)
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

	bool ret = m_socket.open(m_addr);
	if (!ret) {
		LogError("Unable to open the Icom network connection");
		return false;
	}

	LogMessage("Opened the Icom network connection");

	return true;
}

bool CIcomNetwork::write(const unsigned char* data, unsigned int len)
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

	if ((data[9U] & 0x02U) == 0x02U) {
		buffer[37U] = 0x23U;
		buffer[38U] = 0x02U;
		buffer[39U] = 0x18U;
	} else {
		buffer[37U] = 0x23U;
		buffer[38U] = (data[9U] & 0x0CU) != 0x00U ? 0x1CU : 0x10U;
		buffer[39U] = 0x21U;
	}

	::memcpy(buffer + 40U, data + 10U, 33U);

	if (m_debug)
		CUtils::dump(1U, "Icom Network Data Sent", buffer, 102U);

	return m_socket.write(buffer, 102U, m_addr, m_addrLen);
}

unsigned int CIcomNetwork::read(unsigned char* data)
{
	unsigned char buffer[BUFFER_LENGTH];

	sockaddr_storage addr;
	unsigned int addrLen;
	int length = m_socket.read(buffer, BUFFER_LENGTH, addr, addrLen);
	if (length <= 0)
		return 0U;

	// Check if the data is for us
	if (!CUDPSocket::match(m_addr, addr)) {
		LogMessage("Icom packet received from an invalid source");
		return 0U;
	}

	// Invalid packet type?
	if (::memcmp(buffer, "ICOM", 4U) != 0)
		return 0U;

	if (length != 102)
		return 0U;

	if (m_debug)
		CUtils::dump(1U, "Icom Network Data Received", buffer, length);

	::memcpy(data, buffer + 40U, 33U);

	return 33U;
}

void CIcomNetwork::clock(unsigned int ms)
{
}

void CIcomNetwork::close()
{
	m_socket.close();

	LogMessage("Closing Icom network connection");
}
