/*
*   Copyright (C) 2016,2018,2023 by Jonathan Naylor G4KLX
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

#if !defined(NXDNGateway_H)
#define	NXDNGateway_H

#include "NXDNNetwork.h"
#include "APRSWriter.h"
#include "GPSHandler.h"
#include "Reflectors.h"
#include "Voice.h"
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

class CStaticTG {
public:
	unsigned short   m_tg;
	sockaddr_storage m_addr;
	unsigned int     m_addrLen;
};

class CNXDNGateway
{
public:
	CNXDNGateway(const std::string& file);
	~CNXDNGateway();

	void run();

private:
	CConf        m_conf;
	CAPRSWriter* m_writer;
	CGPSHandler* m_gps;
	CVoice*      m_voice;
	CNXDNNetwork* m_remoteNetwork;
	unsigned short m_currentTG;
	unsigned int m_currentAddrLen;
	sockaddr_storage m_currentAddr;
	bool         m_currentIsStatic;
	CTimer       m_hangTimer;
	unsigned int m_rfHangTime;
	CReflectors* m_reflectors;	
	std::vector<CStaticTG> m_staticTGs;

	void createGPS();

	void writeCommand(const std::string& command);

	static void onCommand(const unsigned char* command, unsigned int length);};

#endif

