/*
 *   Copyright (C) 2015,2016,2017,2018,2020 by Jonathan Naylor G4KLX
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

#if !defined(CONF_H)
#define	CONF_H

#include <string>
#include <vector>

class CConf
{
public:
  CConf(const std::string& file);
  ~CConf();

  bool read();

  // The General section
  std::string  getCallsign() const;
  std::string  getSuffix() const;
  std::string  getRptProtocol() const;
  std::string  getRptAddress() const;
  unsigned int getRptPort() const;
  unsigned int getMyPort() const;
  bool         getDebug() const;
  bool         getDaemon() const;

  // The Info section
  unsigned int getRxFrequency() const;
  unsigned int getTxFrequency() const;
  unsigned int getPower() const;
  float        getLatitude() const;
  float        getLongitude() const;
  int          getHeight() const;
  std::string  getName() const;
  std::string  getDescription() const;

  // The Id Lookup section
  std::string  getLookupName() const;
  unsigned int getLookupTime() const;

  // The Voice section
  bool         getVoiceEnabled() const;
  std::string  getVoiceLanguage() const;
  std::string  getVoiceDirectory() const;

  // The APRS section
  bool         getAPRSEnabled() const;
  std::string  getAPRSAddress() const;
  unsigned int getAPRSPort() const;
  std::string  getAPRSSuffix() const;
  std::string  getAPRSDescription() const;

  // The Log section
  unsigned int getLogDisplayLevel() const;
  unsigned int getLogFileLevel() const;
  std::string  getLogFilePath() const;
  std::string  getLogFileRoot() const;

  // The Network section
  unsigned int   getNetworkPort() const;
  std::string    getNetworkHosts1() const;
  std::string    getNetworkHosts2() const;
  unsigned int   getNetworkReloadTime() const;
  std::string    getNetworkParrotAddress() const;
  unsigned int   getNetworkParrotPort() const;
  std::string    getNetworkNXDN2DMRAddress() const;
  unsigned int   getNetworkNXDN2DMRPort() const;
  std::string    getNetworkNXDN2PCMAddress() const;
  unsigned int   getNetworkNXDN2PCMPort() const;
  unsigned short getNetworkStartup() const;
  unsigned int   getNetworkInactivityTimeout() const;
  bool           getNetworkDebug() const;

  // The GPSD section
  bool           getGPSDEnabled() const;
  std::string    getGPSDAddress() const;
  std::string    getGPSDPort() const;

  // The Remote Commands section
  bool           getRemoteCommandsEnabled() const;
  unsigned int   getRemoteCommandsPort() const;

private:
  std::string  m_file;
  std::string  m_callsign;
  std::string  m_suffix;
  std::string  m_rptProtocol;
  std::string  m_rptAddress;
  unsigned int m_rptPort;
  unsigned int m_myPort;
  bool         m_debug;
  bool         m_daemon;

  unsigned int m_rxFrequency;
  unsigned int m_txFrequency;
  unsigned int m_power;
  float        m_latitude;
  float        m_longitude;
  int          m_height;
  std::string  m_name;
  std::string  m_description;

  std::string  m_lookupName;
  unsigned int m_lookupTime;

  bool         m_voiceEnabled;
  std::string  m_voiceLanguage;
  std::string  m_voiceDirectory;

  unsigned int m_logDisplayLevel;
  unsigned int m_logFileLevel;
  std::string  m_logFilePath;
  std::string  m_logFileRoot;

  bool         m_aprsEnabled;
  std::string  m_aprsAddress;
  unsigned int m_aprsPort;
  std::string  m_aprsSuffix;
  std::string  m_aprsDescription;

  unsigned int   m_networkPort;
  std::string    m_networkHosts1;
  std::string    m_networkHosts2;
  unsigned int   m_networkReloadTime;
  std::string    m_networkParrotAddress;
  unsigned int   m_networkParrotPort;
  std::string    m_networkNXDN2DMRAddress;
  unsigned int   m_networkNXDN2DMRPort;
  std::string    m_networkNXDN2PCMAddress;
  unsigned int   m_networkNXDN2PCMPort;
  unsigned short m_networkStartup;
  unsigned int   m_networkInactivityTimeout;
  bool           m_networkDebug;

  bool         m_gpsdEnabled;
  std::string  m_gpsdAddress;
  std::string  m_gpsdPort;

  bool         m_remoteCommandsEnabled;
  unsigned int m_remoteCommandsPort;
};

#endif
