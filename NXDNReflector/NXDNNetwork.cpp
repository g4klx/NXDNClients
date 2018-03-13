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
