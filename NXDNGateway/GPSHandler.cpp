/*
*   Copyright (C) 2018,2020,2025 by Jonathan Naylor G4KLX
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

CGPSHandler::CGPSHandler(const std::string& callsign, const std::string& suffix, CAPRSWriter* writer) :
m_callsign(callsign),
m_writer(writer),
m_data(nullptr),
m_length(0U),
m_source(),
m_suffix(suffix)
{
	assert(!callsign.empty());
	assert(writer != nullptr);

	m_data = new unsigned char[NXDN_DATA_MAX_LENGTH];

	reset();
}

CGPSHandler::~CGPSHandler()
{
	delete[] m_data;
}

void CGPSHandler::processHeader(const std::string& source)
{
	reset();
	m_source = source;
}

void CGPSHandler::processData(const unsigned char* data)
{
	assert(data != nullptr);

	::memcpy(m_data + m_length, data + 1U, NXDN_DATA_LENGTH);
	m_length += NXDN_DATA_LENGTH;

	// The packet frame number and block number are zero to indicate the last section of the
	// data transmission.
	if (data[0U] == 0x00U) {
		bool ret = processIcom();
		if (!ret)
			processKenwood();
		reset();
	}
}

void CGPSHandler::processEnd()
{
	reset();
}

void CGPSHandler::reset()
{
	::memset(m_data, 0x00U, NXDN_DATA_MAX_LENGTH);
	m_length = 0U;
	m_source.clear();
}

bool CGPSHandler::processIcom()
{
	if (m_data[0U] != NXDN_DATA_TYPE_GPS)
		return false;

	if (::memcmp(m_data + 1U, "$G", 2U) != 0)
		return false;

	if (::strchr((char*)(m_data + 1U), '*') == nullptr)
		return false;

	// From here onwards we have something that looks like Icom GPS data

	if (!checkXOR())
		return true;

	if (::memcmp(m_data + 4U, "RMC", 3U) != 0) {
		CUtils::dump("Unhandled NMEA sentence", (unsigned char*)(m_data + 1U), m_length - 1U);
		return true;
	}

	// Parse the $GxRMC string into tokens
	char* pRMC[20U];
	::memset(pRMC, 0x00U, 20U * sizeof(char*));
	unsigned int nRMC = 0U;

	char* p = nullptr;
	char* d = (char*)(m_data + 1U);
	while ((p = ::strtok(d, ",\r\n")) != nullptr && nRMC < 20U) {
		pRMC[nRMC++] = p;
		d = nullptr;
	}

	// Is there any position data?
	if (pRMC[3U] == nullptr || pRMC[4U] == nullptr || pRMC[5U] == nullptr || pRMC[6U] == nullptr || ::strlen(pRMC[3U]) == 0U || ::strlen(pRMC[4U]) == 0U || ::strlen(pRMC[5U]) == 0 || ::strlen(pRMC[6U]) == 0)
		return true;

	// Is it a valid GPS fix?
	if (::strcmp(pRMC[2U], "A") != 0)
		return true;

	double latitude  = ::atof(pRMC[3U]);
	double longitude = ::atof(pRMC[5U]);

	std::string source = m_source;
	if (!m_suffix.empty()) {
		source.append("-");
		source.append(m_suffix.substr(0U, 1U));
	}

	char output[300U];
	if (pRMC[7U] != nullptr && pRMC[8U] != nullptr && ::strlen(pRMC[7U]) > 0U && ::strlen(pRMC[8U]) > 0U) {
		int bearing = ::atoi(pRMC[8U]);
		int speed   = ::atoi(pRMC[7U]);

		::sprintf(output, "%s>APDPRS,NXDN*,qAR,%s:!%07.2lf%s/%08.2lf%sr%03d/%03d Icom IDAS via MMDVM\r\n",
			source.c_str(), m_callsign.c_str(), latitude, pRMC[4U], longitude, pRMC[6U], bearing, speed);
	} else {
		::sprintf(output, "%s>APDPRS,NXDN*,qAR,%s:!%07.2lf%s/%08.2lf%sr Icom IDAS via MMDVM\r\n",
			source.c_str(), m_callsign.c_str(), latitude, pRMC[4U], longitude, pRMC[6U]);
	}

	m_writer->write(output);

	return true;
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

bool CGPSHandler::processKenwood()
{
	enum class GPS {
		FULL,
		SHORT,
		VERY_SHORT
	} type;

	switch (m_data[0U]) {
	case 0x00U:
		if (m_length < 38U)
			return false;
		type = GPS::FULL;
		break;
	case 0x01U:
		if (m_length < 17U)
			return false;
		type = GPS::SHORT;
		break;
	case 0x02U:
		if (m_length < 15U)
			return false;
		type = GPS::VERY_SHORT;
		break;
	default:
		return true;
	}

	unsigned char north    = 'N';
	unsigned int latAfter  = 0x7FFFU;
	unsigned int latBefore = 0xFFFFU;
	unsigned char east     = 'E';
	unsigned int lonAfter  = 0x7FFFU;
	unsigned int lonBefore = 0xFFFFU;
	if (type == GPS::VERY_SHORT) {
		north     = (m_data[7U] & 0x01U) == 0x00U ? 'N' : 'S';
		latAfter  = ((m_data[7U] & 0xFEU) >> 1) | (m_data[8U] << 7);
		latBefore = (m_data[10U] << 8) | m_data[9U];

		east      = (m_data[11U] & 0x01U) == 0x00U ? 'E' : 'W';
		lonAfter  = ((m_data[11U] & 0xFEU) >> 1) | (m_data[12U] << 7);
		lonBefore = (m_data[13U] << 8) | m_data[13U];
	} else {
		north     = (m_data[9U] & 0x01U) == 0x00U ? 'N' : 'S';
		latAfter  = ((m_data[9U] & 0xFEU) >> 1) | (m_data[10U] << 7);
		latBefore = (m_data[12U] << 8) | m_data[11U];

		east      = (m_data[13U] & 0x01U) == 0x00U ? 'E' : 'W';
		lonAfter  = ((m_data[13U] & 0xFEU) >> 1) | (m_data[14U] << 7);
		lonBefore = (m_data[16U] << 8) | m_data[15U];
	}

	if (latAfter == 0x7FFFU || latBefore == 0xFFFFU || lonAfter == 0x7FFFU || lonBefore == 0xFFFFU)
		return true;

	unsigned int course      = 0xFFFFU;
	unsigned int speedBefore = 0x3FFU;
	unsigned int speedAfter  = 0x0FU;
	if (type == GPS::FULL) {
		course      = (m_data[23U] << 4) | (m_data[24U] & 0x0FU);
		speedBefore = ((m_data[25U] & 0xF0U) << 2) | (m_data[26U] & 0x3FU);
		speedAfter  = m_data[25U] & 0x0FU;
	}

	std::string source = m_source;
	if (!m_suffix.empty()) {
		source.append("-");
		source.append(m_suffix.substr(0U, 1U));
	}

	char output[300U];
	if (course != 0xFFFFU && speedBefore != 0x3FFU && speedAfter != 0x0FU) {
		::sprintf(output, "%s>APDPRS,NXDN*,qAR,%s:!%04u.%02u%c/%05u.%02u%cr%03d/%03d Kenwood NEXEDGE via MMDVM\r\n",
			source.c_str(), m_callsign.c_str(), latBefore, latAfter / 100U, north, lonBefore, lonAfter / 100U, east, course / 10U, speedBefore);
	} else {
		::sprintf(output, "%s>APDPRS,NXDN*,qAR,%s:!%04u.%02u%c/%05u.%02u%cr Kenwood NEXEDGE via MMDVM\r\n",
			source.c_str(), m_callsign.c_str(), latBefore, latAfter / 100U, north, lonBefore, lonAfter / 100U, east);
	}

	m_writer->write(output);

	return true;
}
