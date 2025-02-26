/*
*   Copyright (C) 2016,2018,2024 by Jonathan Naylor G4KLX
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

#include "APRSWriter.h"
#include "GPSHandler.h"
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

class CNXDNGateway
{
public:
	CNXDNGateway(const std::string& file);
	~CNXDNGateway();

	int run();

private:
	CConf        m_conf;
	CAPRSWriter* m_writer;
	CGPSHandler* m_gps;
	CVoice*      m_voice;

	void createGPS();

	bool isVoiceBusy() const;
};

#endif
