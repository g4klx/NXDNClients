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

#include "NXDNNetwork.h"

#include <cstdio>
#include <cassert>
#include <cstring>

CNXDNNetwork::CNXDNNetwork(unsigned short port) :
m_socket(port),
m_addr(),
m_addrLen(0U)
{
}

CNXDNNetwork::~CNXDNNetwork()
{
}

bool CNXDNNetwork::open()
{
	::fprintf(stdout, "Opening NXDN network connection\n");

	return m_socket.open();
}

bool CNXDNNetwork::write(const unsigned char* data, unsigned int length)
{
	if (m_addrLen == 0U)
		return true;

	assert(data != nullptr);

	return m_socket.write(data, length, m_addr, m_addrLen);
}

unsigned int CNXDNNetwork::read(unsigned char* data, unsigned int len)
{
	sockaddr_storage addr;
	unsigned int addrlen;
	int length = m_socket.read(data, len, addr, addrlen);
	if (length <= 0)
		return 0U;

	m_addr    = addr;
	m_addrLen = addrlen;

	if (::memcmp(data, "NXDNP", 5U) == 0 && length == 17) {			// A poll
		write(data, length);
		return 0U;
	} else if (::memcmp(data, "NXDND", 5U) == 0 && length == 43) {
		return 43U;
	} else {
		return 0U;
	}
}

void CNXDNNetwork::end()
{
	m_addrLen = 0U;
}

void CNXDNNetwork::close()
{
	m_socket.close();

	::fprintf(stdout, "Closing NXDN network connection\n");
}
