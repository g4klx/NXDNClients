/*
*   Copyright (C) 2018 by Jonathan Naylor G4KLX
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

#include "GPSHandler.h"
#include "Utils.h"

#include <cstdint>
#include <cstdio>
#include <cassert>
#include <cstring>

const unsigned char NXDN_DATA_TYPE_GPS = 0x06U;

const unsigned int NXDN_DATA_LENGTH = 20U;
const unsigned int NXDN_DATA_MAX_LENGTH = 16U * NXDN_DATA_LENGTH;

CGPSHandler::CGPSHandler(const std::string& callsign, const std::string& suffix, const std::string& password, const std::string& address, unsigned int port) :
m_callsign(callsign),
m_writer(callsign, suffix, password, address, port),
m_data(NULL),
m_length(0U),
m_source()
{
	assert(!callsign.empty());
	assert(!password.empty());
	assert(!address.empty());
	assert(port > 0U);

	m_data = new unsigned char[NXDN_DATA_MAX_LENGTH];

	reset();
}

CGPSHandler::~CGPSHandler()
{
	delete[] m_data;
}

bool CGPSHandler::open()
{
	return m_writer.open();
}

void CGPSHandler::setInfo(unsigned int txFrequency, unsigned int rxFrequency, float latitude, float longitude, int height, const std::string& desc)
{
	m_writer.setInfo(txFrequency, rxFrequency, latitude, longitude, height, desc);
}

void CGPSHandler::processHeader(const std::string& source)
{
	reset();
	m_source = source;
}

void CGPSHandler::processData(const unsigned char* data)
{
	assert(data != NULL);

	::memcpy(m_data + m_length, data + 1U, NXDN_DATA_LENGTH);
	m_length += NXDN_DATA_LENGTH;

	if (data[0U] == 0x00U) {
		processNMEA();
		reset();
	}
}

void CGPSHandler::processEnd()
{
	reset();
}

void CGPSHandler::clock(unsigned int ms)
{
	m_writer.clock(ms);
}

void CGPSHandler::close()
{
	m_writer.close();
}

void CGPSHandler::reset()
{
	::memset(m_data, 0x00U, NXDN_DATA_MAX_LENGTH);
	m_length = 0U;
	m_source.clear();
}

void CGPSHandler::processNMEA()
{
	if (m_data[0U] != NXDN_DATA_TYPE_GPS)
		return;

	if (::memcmp(m_data + 1U, "$G", 2U) != 0)
		return;

	if (::strchr((char*)(m_data + 1U), '*') == NULL)
		return;

	if (!checkXOR())
		return;

	if (::memcmp(m_data + 4U, "RMC", 3U) != 0) {
		CUtils::dump("Unhandled NMEA sentence", (unsigned char*)(m_data + 1U), m_length - 1U);
		return;
	}

	// Parse the $GxRMC string into tokens
	char* pRMC[20U];
	::memset(pRMC, 0x00U, 20U * sizeof(char*));
	unsigned int nRMC = 0U;

	char* p = NULL;
	char* d = (char*)(m_data + 1U);
	while ((p = ::strtok(d, ",\r\n")) != NULL) {
		pRMC[nRMC++] = p;
		d = NULL;
	}

	// Is there any position data?
	if (pRMC[3U] == NULL || pRMC[4U] == NULL || pRMC[5U] == NULL || pRMC[6U] == NULL || ::strlen(pRMC[3U]) == 0U || ::strlen(pRMC[4U]) == 0U || ::strlen(pRMC[5U]) == 0 || ::strlen(pRMC[6U]) == 0)
		return;

	// Is it a valid GPS fix?
	if (::strcmp(pRMC[2U], "A") != 0)
		return;

	double latitude  = ::atof(pRMC[3U]);
	double longitude = ::atof(pRMC[5U]);

	char output[300U];
	if (pRMC[7U] != NULL && pRMC[8U] != NULL && ::strlen(pRMC[7U]) > 0U && ::strlen(pRMC[8U]) > 0U) {
		int bearing = ::atoi(pRMC[8U]);
		int speed   = ::atoi(pRMC[7U]);

		::sprintf(output, "%s-N>APDPRS,NXDN*,qAR,%s:!%07.2lf%s/%08.2lf%sr%03d/%03d via MMDVM",
			m_source.c_str(), m_callsign.c_str(), latitude, pRMC[4U], longitude, pRMC[6U], bearing, speed);
	} else {
		::sprintf(output, "%s-N>APDPRS,NXDN*,qAR,%s:!%07.2lf%s/%08.2lf%sr via MMDVM",
			m_source.c_str(), m_callsign.c_str(), latitude, pRMC[4U], longitude, pRMC[6U]);
	}

	m_writer.write(output);
}

bool CGPSHandler::checkXOR() const
{
	char* p1 = ::strchr((char*)m_data, '$');
	char* p2 = ::strchr((char*)m_data, '*');

	unsigned char res = 0U;
	for (char* q = p1 + 1U; q < p2; q++)
		res ^= *q;

	char buffer[10U];
	::sprintf(buffer, "%02X", res);

	return ::memcmp(buffer, p2 + 1U, 2U) == 0;
}
