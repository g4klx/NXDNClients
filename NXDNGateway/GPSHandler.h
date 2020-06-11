/*
*   Copyright (C) 2018,2020 by Jonathan Naylor G4KLX
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

#ifndef	GPSHandler_H
#define	GPSHandler_H

#include "APRSWriter.h"

#include <string>

class CGPSHandler {
public:
	CGPSHandler(const std::string& callsign, const std::string& suffix, CAPRSWriter* writer);
	~CGPSHandler();

	void processHeader(const std::string& source);

	void processData(const unsigned char* data);

	void processEnd();

private:
	std::string    m_callsign;
	CAPRSWriter*   m_writer;
	unsigned char* m_data;
	unsigned int   m_length;
	std::string    m_source;
	std::string    m_suffix;

	bool processIcom();
	bool processKenwood();
	bool checkXOR() const;
	void reset();
};

#endif
