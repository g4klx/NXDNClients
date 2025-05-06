/*
*   Copyright (C) 2016,2018,2020,2025 by Jonathan Naylor G4KLX
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

#if !defined(Reflectors_H)
#define	Reflectors_H

#include "UDPSocket.h"
#include "Timer.h"

#include <vector>
#include <string>

#include <cstring>

class CNXDNReflector {
public:
	CNXDNReflector() :
	m_id(0U)
	{
		IPv4.m_addrLen = 0U;
		IPv6.m_addrLen = 0U;
	}

	CNXDNReflector(const CNXDNReflector& in)
	{
		m_id = in.m_id;

		IPv4.m_addrLen = in.IPv4.m_addrLen;
		IPv6.m_addrLen = in.IPv6.m_addrLen;

		::memcpy(&IPv4.m_addr, &in.IPv4.m_addr, sizeof(sockaddr_storage));
		::memcpy(&IPv6.m_addr, &in.IPv6.m_addr, sizeof(sockaddr_storage));
	}

	bool isEmpty() const
	{
		return m_id == 0U;
	}

	bool isUsed() const
	{
		return m_id > 0U;
	}

	void reset()
	{
		m_id = 0U;
	}

	bool hasIPv4() const
	{
		return IPv4.m_addrLen > 0U;
	}

	bool hasIPv6() const
	{
		return IPv6.m_addrLen > 0U;
	}

	unsigned short       m_id;
	struct {
		sockaddr_storage m_addr;
		unsigned int     m_addrLen;
	} IPv4;
	struct {
		sockaddr_storage m_addr;
		unsigned int     m_addrLen;
	} IPv6;

	CNXDNReflector& operator=(const CNXDNReflector& in)
	{
		if (&in != this) {
			m_id = in.m_id;

			IPv4.m_addrLen = in.IPv4.m_addrLen;
			IPv6.m_addrLen = in.IPv6.m_addrLen;

			::memcpy(&IPv4.m_addr, &in.IPv4.m_addr, sizeof(sockaddr_storage));
			::memcpy(&IPv6.m_addr, &in.IPv6.m_addr, sizeof(sockaddr_storage));
		}

		return *this;
	}
};

class CReflectors {
public:
	CReflectors(const std::string& hostsFile1, const std::string& hostsFile2, unsigned int reloadTime);
	~CReflectors();

	void setParrot(const std::string& address, unsigned short port);
	void setNXDN2DMR(const std::string& address, unsigned short port);

	bool load();

	CNXDNReflector* find(unsigned short id);

	void clock(unsigned int ms);

private:
	std::string  m_hostsFile1;
	std::string  m_hostsFile2;
	std::string  m_parrotAddress;
	unsigned short m_parrotPort;
	std::string  m_nxdn2dmrAddress;
	unsigned short m_nxdn2dmrPort;
	std::vector<CNXDNReflector*> m_reflectors;
	CTimer       m_timer;

	void remove();
	bool parseJSON(const std::string& fileName);
	bool parseHosts(const std::string& fileName);
};

#endif
