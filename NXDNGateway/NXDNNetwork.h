/*
 *   Copyright (C) 2009-2014,2016,2020,2024,2025 by Jonathan Naylor G4KLX
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

#ifndef	NXDNNetwork_H
#define	NXDNNetwork_H

#include "Reflectors.h"
#include "UDPSocket.h"

#include <cstdint>
#include <string>

class CNXDNNetwork {
public:
	CNXDNNetwork(unsigned short port, const std::string& callsign, bool debug);
	~CNXDNNetwork();

	bool open();

	bool writeData(const unsigned char* data, unsigned int length, unsigned short srcId, unsigned short dstId, bool grp, const CNXDNReflector& address);

	unsigned int readData(unsigned char* data, unsigned int length, sockaddr_storage& addr, unsigned int& addrLen);

	bool writePoll(const CNXDNReflector& address);

	bool writeUnlink(const CNXDNReflector& address);

	void close();

	bool hasIPv4() const;
	bool hasIPv6() const;

	static bool match(const sockaddr_storage& address, const CNXDNReflector& reflector);

private:
	std::string m_callsign;
	CUDPSocket* m_socket4;
	CUDPSocket* m_socket6;
	bool        m_debug;
};

#endif
