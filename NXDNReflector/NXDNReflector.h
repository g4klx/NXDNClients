/*
*   Copyright (C) 2016,2018,2020 by Jonathan Naylor G4KLX
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

#if !defined(NXDNReflector_H)
#define	NXDNReflector_H

#include "KenwoodNetwork.h"
#include "IcomNetwork.h"
#include "Timer.h"
#include "Conf.h"

#include <cstdio>
#include <string>
#include <vector>

#if !defined(_WIN32) && !defined(_WIN64)
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock.h>
#endif

class CNXDNRepeater {
public:
	CNXDNRepeater() :
	m_addr(),
	m_addrLen(0U),
	m_callsign(),
	m_timer(1000U, 120U)
	{
	}

	sockaddr_storage m_addr;
	unsigned int     m_addrLen;
	std::string      m_callsign;
	CTimer           m_timer;
};

class CNXDNReflector
{
public:
	CNXDNReflector(const std::string& file);
	~CNXDNReflector();

	void run();

private:
	CConf                       m_conf;
	CIcomNetwork*               m_icomNetwork;
	CKenwoodNetwork*            m_kenwoodNetwork;
	std::vector<CNXDNRepeater*> m_repeaters;

	CNXDNRepeater* findRepeater(const sockaddr_storage& addr) const;
	void dumpRepeaters() const;

	bool openIcomNetwork();
	bool openKenwoodNetwork();
	void closeIcomNetwork();
	void closeKenwoodNetwork();
};

#endif
