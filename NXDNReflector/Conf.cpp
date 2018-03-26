/*
 *   Copyright (C) 2015,2016,2018 by Jonathan Naylor G4KLX
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

#include "Conf.h"
#include "Log.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>

const int BUFFER_SIZE = 500;

enum SECTION {
  SECTION_NONE,
  SECTION_GENERAL,
  SECTION_ID_LOOKUP,
  SECTION_LOG,
  SECTION_NETWORK,
  SECTION_NXCORE
};

CConf::CConf(const std::string& file) :
m_file(file),
m_tg(9999U),
m_daemon(false),
m_lookupName(),
m_lookupTime(0U),
m_logDisplayLevel(0U),
m_logFileLevel(0U),
m_logFilePath(),
m_logFileRoot(),
m_networkPort(0U),
m_networkDebug(false),
m_nxCoreEnabled(false),
m_nxCoreAddress(),
m_nxCoreTGEnable(0U),
m_nxCoreTGDisable(0U),
m_nxCoreDebug(false)
{
}

CConf::~CConf()
{
}

bool CConf::read()
{
  FILE* fp = ::fopen(m_file.c_str(), "rt");
  if (fp == NULL) {
    ::fprintf(stderr, "Couldn't open the .ini file - %s\n", m_file.c_str());
    return false;
  }

  SECTION section = SECTION_NONE;

  char buffer[BUFFER_SIZE];
  while (::fgets(buffer, BUFFER_SIZE, fp) != NULL) {
	  if (buffer[0U] == '#')
		  continue;

	  if (buffer[0U] == '[') {
		  if (::strncmp(buffer, "[General]", 9U) == 0)
			  section = SECTION_GENERAL;
		  else if (::strncmp(buffer, "[Id Lookup]", 11U) == 0)
			  section = SECTION_ID_LOOKUP;
		  else if (::strncmp(buffer, "[Log]", 5U) == 0)
			  section = SECTION_LOG;
		  else if (::strncmp(buffer, "[Network]", 9U) == 0)
			  section = SECTION_NETWORK;
		  else if (::strncmp(buffer, "[NXCore]", 8U) == 0)
			  section = SECTION_NXCORE;
		  else
			  section = SECTION_NONE;

		  continue;
	  }

	  char* key = ::strtok(buffer, " \t=\r\n");
	  if (key == NULL)
		  continue;

	  char* value = ::strtok(NULL, "\r\n");
	  if (section == SECTION_GENERAL) {
		  if (::strcmp(key, "Daemon") == 0)
			  m_daemon = ::atoi(value) == 1;
		  else if (::strcmp(key, "TG") == 0)
			  m_tg = (unsigned short)::atoi(value);
	  } else if (section == SECTION_ID_LOOKUP) {
		  if (::strcmp(key, "Name") == 0)
			  m_lookupName = value;
		  else if (::strcmp(key, "Time") == 0)
			  m_lookupTime = (unsigned int)::atoi(value);
	  } else if (section == SECTION_LOG) {
		  if (::strcmp(key, "FilePath") == 0)
			  m_logFilePath = value;
		  else if (::strcmp(key, "FileRoot") == 0)
			  m_logFileRoot = value;
		  else if (::strcmp(key, "FileLevel") == 0)
			  m_logFileLevel = (unsigned int)::atoi(value);
		  else if (::strcmp(key, "DisplayLevel") == 0)
			  m_logDisplayLevel = (unsigned int)::atoi(value);
	  } else if (section == SECTION_NETWORK) {
		  if (::strcmp(key, "Port") == 0)
			  m_networkPort = (unsigned int)::atoi(value);
		  else if (::strcmp(key, "Debug") == 0)
			  m_networkDebug = ::atoi(value) == 1;
	  } else if (section == SECTION_NXCORE) {
		  if (::strcmp(key, "Enabled") == 0)
			  m_nxCoreEnabled = ::atoi(value) == 1;
		  else if (::strcmp(key, "Address") == 0)
			  m_nxCoreAddress = value;
		  else if (::strcmp(key, "TGEnable") == 0)
			  m_nxCoreTGEnable = (unsigned short)::atoi(value);
		  else if (::strcmp(key, "TGDisable") == 0)
			  m_nxCoreTGDisable = (unsigned short)::atoi(value);
		  else if (::strcmp(key, "Debug") == 0)
			  m_nxCoreDebug = ::atoi(value) == 1;
	  }
  }

  ::fclose(fp);

  return true;
}

bool CConf::getDaemon() const
{
	return m_daemon;
}

unsigned short CConf::getTG() const
{
	return m_tg;
}

std::string CConf::getLookupName() const
{
	return m_lookupName;
}

unsigned int CConf::getLookupTime() const
{
	return m_lookupTime;
}

unsigned int CConf::getLogDisplayLevel() const
{
	return m_logDisplayLevel;
}

unsigned int CConf::getLogFileLevel() const
{
	return m_logFileLevel;
}

std::string CConf::getLogFilePath() const
{
  return m_logFilePath;
}

std::string CConf::getLogFileRoot() const
{
  return m_logFileRoot;
}

unsigned int CConf::getNetworkPort() const
{
	return m_networkPort;
}

bool CConf::getNetworkDebug() const
{
	return m_networkDebug;
}

bool CConf::getNXCoreEnabled() const
{
	return m_nxCoreEnabled;
}

std::string CConf::getNXCoreAddress() const
{
	return m_nxCoreAddress;
}

unsigned short CConf::getNXCoreTGEnable() const
{
	return m_nxCoreTGEnable;
}

unsigned short CConf::getNXCoreTGDisable() const
{
	return m_nxCoreTGDisable;
}

bool CConf::getNXCoreDebug() const
{
	return m_nxCoreDebug;
}
