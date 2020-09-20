/*
 *   Copyright (C) 2009-2014,2016,2018,2020 by Jonathan Naylor G4KLX
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

#ifndef	RptNetwork_H
#define	RptNetwork_H

#if !defined(_WIN32) && !defined(_WIN64)
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#else
#include <WS2tcpip.h>
#endif

#include <cstdint>
#include <string>

class IRptNetwork {
public:
	virtual ~IRptNetwork() = 0;

	virtual bool open() = 0;

	virtual bool write(const unsigned char* data, unsigned int length) = 0;

	virtual unsigned int read(unsigned char* data) = 0;

	virtual void close() = 0;

	virtual void clock(unsigned int ms) = 0;

private:
};

#endif
