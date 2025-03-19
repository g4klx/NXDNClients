/*
 *   Copyright (C) 2010-2014,2016,2017,2018,2020,2023,2025 by Jonathan Naylor G4KLX
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

#include "APRSWriter.h"
#include "MQTTConnection.h"
#include "Log.h"

#include <cstdio>
#include <cassert>
#include <cstring>
#include <cmath>

// In Log.cpp
extern CMQTTConnection* m_mqtt;

CAPRSWriter::CAPRSWriter(const std::string& callsign, const std::string& suffix, bool debug) :
m_idTimer(1000U),
m_callsign(callsign),
m_debug(debug),
m_txFrequency(0U),
m_rxFrequency(0U),
m_latitude(0.0F),
m_longitude(0.0F),
m_height(0),
m_desc(),
m_symbol()
#if defined(USE_GPSD)
,m_gpsdEnabled(false),
m_gpsdAddress(),
m_gpsdPort(),
m_gpsdData()
#endif
{
	assert(!callsign.empty());

	if (!suffix.empty()) {
		m_callsign.append("-");
		m_callsign.append(suffix.substr(0U, 1U));
	}
}

CAPRSWriter::~CAPRSWriter()
{
}

void CAPRSWriter::setInfo(unsigned int txFrequency, unsigned int rxFrequency, const std::string& desc, const std::string& symbol)
{
	m_txFrequency = txFrequency;
	m_rxFrequency = rxFrequency;
	m_desc        = desc;
	m_symbol      = symbol;
}

void CAPRSWriter::setStaticLocation(float latitude, float longitude, int height)
{
	m_latitude  = latitude;
	m_longitude = longitude;
	m_height    = height;
}

void CAPRSWriter::setGPSDLocation(const std::string& address, const std::string& port)
{
#if defined(USE_GPSD)
	assert(!address.empty());
	assert(!port.empty());

	m_gpsdEnabled = true;
	m_gpsdAddress = address;
	m_gpsdPort    = port;
#endif
}

bool CAPRSWriter::open()
{
#if defined(USE_GPSD)
	if (m_gpsdEnabled) {
		int ret = ::gps_open(m_gpsdAddress.c_str(), m_gpsdPort.c_str(), &m_gpsdData);
		if (ret != 0) {
			LogError("Error when opening access to gpsd - %d - %s", errno, ::gps_errstr(errno));
			return false;
		}

		::gps_stream(&m_gpsdData, WATCH_ENABLE | WATCH_JSON, nullptr);

		LogMessage("Connected to GPSD");
	}
#endif
	m_idTimer.setTimeout(60U);
	m_idTimer.start();

	return true;
}

void CAPRSWriter::write(const char* data)
{
	assert(data != nullptr);

	if (m_debug)
		LogDebug("APRS ==> %s", data);

	m_mqtt->publish("aprs-gateway/aprs", data);
}

void CAPRSWriter::clock(unsigned int ms)
{
	m_idTimer.clock(ms);

#if defined(USE_GPSD)
	if (m_gpsdEnabled) {
		if (m_idTimer.hasExpired()) {
			sendIdFrameMobile();
			m_idTimer.start();
		}

	} else {
#endif
		if (m_idTimer.hasExpired()) {
			sendIdFrameFixed();
			m_idTimer.setTimeout(20U * 60U);
			m_idTimer.start();
		}
#if defined(USE_GPSD)
	}
#endif
}

void CAPRSWriter::close()
{
#if defined(USE_GPSD)
	if (m_gpsdEnabled) {
		::gps_stream(&m_gpsdData, WATCH_DISABLE, nullptr);
		::gps_close(&m_gpsdData);
	}
#endif
}

void CAPRSWriter::sendIdFrameFixed()
{
	// Default values aren't passed on
	if (m_latitude == 0.0F && m_longitude == 0.0F)
		return;

	char desc[200U];
	if (m_txFrequency != 0U) {
		float offset = float(int(m_rxFrequency) - int(m_txFrequency)) / 1000000.0F;
		::sprintf(desc, "MMDVM Voice (NXDN) %.5LfMHz %c%.4lfMHz%s%s",
			(long double)(m_txFrequency) / 1000000.0F,
			offset < 0.0F ? '-' : '+',
			::fabs(offset), m_desc.empty() ? "" : ", ", m_desc.c_str());
	} else {
		::sprintf(desc, "MMDVM Voice (NXDN)%s%s", m_desc.empty() ? "" : ", ", m_desc.c_str());
	}

	const char* band = "4m";
	if (m_txFrequency >= 1200000000U)
		band = "23cm/1.2GHz";
	else if (m_txFrequency >= 420000000U)
		band = "70cm";
	else if (m_txFrequency >= 144000000U)
		band = "2m";
	else if (m_txFrequency >= 50000000U)
		band = "6m";
	else if (m_txFrequency >= 28000000U)
		band = "10m";

	double tempLat  = ::fabs(m_latitude);
	double tempLong = ::fabs(m_longitude);

	double latitude  = ::floor(tempLat);
	double longitude = ::floor(tempLong);

	latitude  = (tempLat  - latitude)  * 60.0 + latitude  * 100.0;
	longitude = (tempLong - longitude) * 60.0 + longitude * 100.0;

	char lat[20U];
	::sprintf(lat, "%07.2lf", latitude);

	char lon[20U];
	::sprintf(lon, "%08.2lf", longitude);

	std::string server = m_callsign;
	std::string symbol = m_symbol;
	size_t pos = server.find_first_of('-');
	if (pos == std::string::npos)
		server.append("-S");
	else
		server.append("S");

        if (symbol.empty())
                symbol.append("D&");

	char output[500U];
	::sprintf(output, "%s>APDG04,TCPIP*,qAC,%s:!%s%c%c%s%c%c/A=%06.0f%s %s\r\n",
		m_callsign.c_str(), server.c_str(),
		lat, (m_latitude < 0.0F)  ? 'S' : 'N', symbol[0],
		lon, (m_longitude < 0.0F) ? 'W' : 'E', symbol[1],
		float(m_height) * 3.28F, band, desc);

	write(output);
}

#if defined(USE_GPSD)
void CAPRSWriter::sendIdFrameMobile()
{
	if (!::gps_waiting(&m_gpsdData, 0))
		return;

#if GPSD_API_MAJOR_VERSION >= 7
	if (::gps_read(&m_gpsdData, nullptr, 0) <= 0)
		return;
#else
	if (::gps_read(&m_gpsdData) <= 0)
		return;
#endif

#if GPSD_API_MAJOR_VERSION >= 10
	if (m_gpsdData.fix.status != STATUS_FIX)
#else
	if (m_gpsdData.status != STATUS_FIX)
#endif
		return;

	bool latlonSet   = (m_gpsdData.set & LATLON_SET) == LATLON_SET;
	bool altitudeSet = (m_gpsdData.set & ALTITUDE_SET) == ALTITUDE_SET;
	bool velocitySet = (m_gpsdData.set & SPEED_SET) == SPEED_SET;
	bool bearingSet  = (m_gpsdData.set & TRACK_SET) == TRACK_SET;

	if (!latlonSet)
		return;

	float rawLatitude  = float(m_gpsdData.fix.latitude);
	float rawLongitude = float(m_gpsdData.fix.longitude);
#if GPSD_API_MAJOR_VERSION >= 9
	float rawAltitude  = float(m_gpsdData.fix.altMSL);
#else
	float rawAltitude  = float(m_gpsdData.fix.altitude);
#endif
	float rawVelocity  = float(m_gpsdData.fix.speed);
	float rawBearing   = float(m_gpsdData.fix.track);

	char desc[200U];
	if (m_txFrequency != 0U) {
		float offset = float(int(m_rxFrequency) - int(m_txFrequency)) / 1000000.0F;
		::sprintf(desc, "MMDVM Voice (NXDN) %.5LfMHz %c%.4lfMHz%s%s",
			(long double)(m_txFrequency) / 1000000.0F,
			offset < 0.0F ? '-' : '+',
			::fabs(offset), m_desc.empty() ? "" : ", ", m_desc.c_str());
	} else {
		::sprintf(desc, "MMDVM Voice (NXDN)%s%s", m_desc.empty() ? "" : ", ", m_desc.c_str());
	}

	const char* band = "4m";
	if (m_txFrequency >= 1200000000U)
		band = "23cm/1.2GHz";
	else if (m_txFrequency >= 420000000U)
		band = "70cm";
	else if (m_txFrequency >= 144000000U)
		band = "2m";
	else if (m_txFrequency >= 50000000U)
		band = "6m";
	else if (m_txFrequency >= 28000000U)
		band = "10m";

	double tempLat  = ::fabs(rawLatitude);
	double tempLong = ::fabs(rawLongitude);

	double latitude  = ::floor(tempLat);
	double longitude = ::floor(tempLong);

	latitude  = (tempLat  - latitude)  * 60.0 + latitude  * 100.0;
	longitude = (tempLong - longitude) * 60.0 + longitude * 100.0;

	char lat[20U];
	::sprintf(lat, "%07.2lf", latitude);

	char lon[20U];
	::sprintf(lon, "%08.2lf", longitude);

	std::string server = m_callsign;
	std::string symbol = m_symbol;
	size_t pos = server.find_first_of('-');
	if (pos == std::string::npos)
		server.append("-S");
	else
		server.append("S");

        if (symbol.empty())
                symbol.append("D&");

	char output[500U];
	::sprintf(output, "%s>APDG03,TCPIP*,qAC,%s:!%s%c%c%s%c%c",
		m_callsign.c_str(), server.c_str(),
		lat, (rawLatitude < 0.0F)  ? 'S' : 'N', symbol[0],
		lon, (rawLongitude < 0.0F) ? 'W' : 'E',symbol[0]);

	if (bearingSet && velocitySet)
		::sprintf(output + ::strlen(output), "%03.0f/%03.0f", rawBearing, rawVelocity * 0.539957F);

	if (altitudeSet)
		::sprintf(output + ::strlen(output), "/A=%06.0f", float(rawAltitude) * 3.28F);

	::sprintf(output + ::strlen(output), "%s %s\r\n", band, desc);

	write(output);
}
#endif
