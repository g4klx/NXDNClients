/*
*   Copyright (C) 2016,2018 by Jonathan Naylor G4KLX
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

#include "NXDNReflector.h"
#include "NXDNNetwork.h"
#include "NXDNLookup.h"
#include "StopWatch.h"
#include "Version.h"
#include "Thread.h"
#include "Utils.h"
#include "Log.h"

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
const char* DEFAULT_INI_FILE = "NXDNReflector.ini";
#else
const char* DEFAULT_INI_FILE = "/etc/NXDNReflector.ini";
#endif

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <ctime>
#include <cstring>
#include <algorithm>

int main(int argc, char** argv)
{
	const char* iniFile = DEFAULT_INI_FILE;
	if (argc > 1) {
		for (int currentArg = 1; currentArg < argc; ++currentArg) {
			std::string arg = argv[currentArg];
			if ((arg == "-v") || (arg == "--version")) {
				::fprintf(stdout, "NXDNReflector version %s\n", VERSION);
				return 0;
			} else if (arg.substr(0, 1) == "-") {
				::fprintf(stderr, "Usage: NXDNReflector [-v|--version] [filename]\n");
				return 1;
			} else {
				iniFile = argv[currentArg];
			}
		}
	}

	CNXDNReflector* reflector = new CNXDNReflector(std::string(iniFile));
	reflector->run();
	delete reflector;

	return 0;
}

CNXDNReflector::CNXDNReflector(const std::string& file) :
m_conf(file),
m_nxCoreNetwork(NULL),
m_repeaters()
{
}

CNXDNReflector::~CNXDNReflector()
{
}

void CNXDNReflector::run()
{
	bool ret = m_conf.read();
	if (!ret) {
		::fprintf(stderr, "NXDNReflector: cannot read the .ini file\n");
		return;
	}

	ret = ::LogInitialise(m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel());
	if (!ret) {
		::fprintf(stderr, "NXDNReflector: unable to open the log file\n");
		return;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	bool m_daemon = m_conf.getDaemon();
	if (m_daemon) {
		// Create new process
		pid_t pid = ::fork();
		if (pid == -1) {
			::LogWarning("Couldn't fork() , exiting");
			return;
		}
		else if (pid != 0)
			exit(EXIT_SUCCESS);

		// Create new session and process group
		if (::setsid() == -1) {
			::LogWarning("Couldn't setsid(), exiting");
			return;
		}

		// Set the working directory to the root directory
		if (::chdir("/") == -1) {
			::LogWarning("Couldn't cd /, exiting");
			return;
		}

		::close(STDIN_FILENO);
		::close(STDOUT_FILENO);
		::close(STDERR_FILENO);

		//If we are currently root...
		if (getuid() == 0) {
			struct passwd* user = ::getpwnam("mmdvm");
			if (user == NULL) {
				::LogError("Could not get the mmdvm user, exiting");
				return;
			}

			uid_t mmdvm_uid = user->pw_uid;
			gid_t mmdvm_gid = user->pw_gid;

			//Set user and group ID's to mmdvm:mmdvm
			if (setgid(mmdvm_gid) != 0) {
				::LogWarning("Could not set mmdvm GID, exiting");
				return;
			}

			if (setuid(mmdvm_uid) != 0) {
				::LogWarning("Could not set mmdvm UID, exiting");
				return;
			}

			//Double check it worked (AKA Paranoia) 
			if (setuid(0) != -1) {
				::LogWarning("It's possible to regain root - something is wrong!, exiting");
				return;
			}
		}
	}
#endif

	CNXDNNetwork nxdnNetwork(m_conf.getNetworkPort(), m_conf.getNetworkDebug());
	ret = nxdnNetwork.open();
	if (!ret) {
		::LogFinalise();
		return;
	}

	unsigned short nxCoreTGEnable = 0U;
	unsigned short nxCoreTGDisable = 0U;

	if (m_conf.getNXCoreEnabled()) {
		ret = openNXCore();
		if (!ret) {
			nxdnNetwork.close();
			::LogFinalise();
			return;
		}

		nxCoreTGEnable  = m_conf.getNXCoreTGEnable();
		nxCoreTGDisable = m_conf.getNXCoreTGDisable();
	}

	CNXDNLookup* lookup = new CNXDNLookup(m_conf.getLookupName(), m_conf.getLookupTime());
	lookup->read();

	CStopWatch stopWatch;
	stopWatch.start();

	CTimer dumpTimer(1000U, 120U);
	dumpTimer.start();

	LogMessage("Starting NXDNReflector-%s", VERSION);

	CNXDNRepeater* current = NULL;
	bool nxCoreActive = false;

	unsigned short srcId = 0U;
	unsigned short dstId = 0U;
	bool grp = false;

	CTimer watchdogTimer(1000U, 0U, 1500U);

	for (;;) {
		unsigned char buffer[200U];
		in_addr address;
		unsigned int port;

		unsigned int len = nxdnNetwork.read(buffer, 200U, address, port);
		if (len > 0U) {
			CNXDNRepeater* rpt = findRepeater(address, port);

			if (::memcmp(buffer, "NXDNP", 5U) == 0 && len == 15U) {
				if (rpt == NULL) {
					rpt = new CNXDNRepeater;
					rpt->m_timer.start();
					rpt->m_address = address;
					rpt->m_port = port;
					rpt->m_callsign = std::string((char*)(buffer + 5U), 10U);
					m_repeaters.push_back(rpt);

					LogMessage("Adding %s (%s:%u)", rpt->m_callsign.c_str(), ::inet_ntoa(address), port);
				} else {
					rpt->m_timer.start();
				}

				// Return the poll
				nxdnNetwork.write(buffer, len, address, port);
			} else if (::memcmp(buffer, "NXDNU", 5U) == 0 && len == 15U) {
				if (rpt != NULL) {
					std::string callsign = std::string((char*)(buffer + 5U), 10U);
					LogMessage("Removing %s (%s:%u)", callsign.c_str(), ::inet_ntoa(address), port);

					for (std::vector<CNXDNRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
						if (*it == rpt) {
							m_repeaters.erase(it);
							break;
						}
					}

					delete rpt;
				}
			} else if (::memcmp(buffer, "NXDND", 5U) == 0 && len == 43U) {
				if (rpt != NULL) {
					unsigned short srcId = (buffer[5U] << 8) | buffer[6U];
					unsigned short dstId = (buffer[7U] << 8) | buffer[8U];
					bool grp = (buffer[9U] & 0x01U) == 0x01U;

					if (nxCoreTGEnable != 0U && grp && dstId == nxCoreTGEnable) {
						if (m_nxCoreNetwork == NULL) {
							std::string callsign = lookup->find(srcId);
							LogMessage("NXCore link enabled by %s at %s", callsign.c_str(), current->m_callsign.c_str());
							bool ok = openNXCore();
							if (!ok)
								LogWarning("Unable to open the NXCore link");
						}
					} else if (nxCoreTGDisable != 0U && grp && dstId == nxCoreTGDisable) {
						if (m_nxCoreNetwork != NULL) {
							std::string callsign = lookup->find(srcId);
							LogMessage("NXCore link disabled by %s at %s", callsign.c_str(), current->m_callsign.c_str());
							closeNXCore();
						}
					} else {
						rpt->m_timer.start();

						if (current == NULL && !nxCoreActive) {
							current = rpt;

							std::string callsign = lookup->find(srcId);
							LogMessage("Transmission from %s at %s to %s%u", callsign.c_str(), current->m_callsign.c_str(), grp ? "TG " : "", dstId);
						}

						if (current == rpt) {
							watchdogTimer.start();

							for (std::vector<CNXDNRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
								in_addr addr = (*it)->m_address;
								unsigned int prt = (*it)->m_port;
								if (addr.s_addr != address.s_addr || prt != port)
									nxdnNetwork.write(buffer, len, addr, prt);
							}

							if (m_nxCoreNetwork != NULL)
								m_nxCoreNetwork->write(buffer, len);

							if ((buffer[9U] & 0x08U) == 0x08U) {
								LogMessage("Received end of transmission");
								watchdogTimer.stop();
								current = NULL;
							}
						}
					}
				} else {
					LogMessage("Data received from an unknown source - %s:%u", ::inet_ntoa(address), port);
					CUtils::dump(2U, "Data", buffer, len);
				}
			}
		}

		if (m_nxCoreNetwork != NULL) {
			len = m_nxCoreNetwork->read(buffer, 200U);
			if (len > 0U) {
				if (current == NULL) {
					if (!nxCoreActive) {
						if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && buffer[5U] == 0x01U) {
							// Save the grp, src and dest for use in the NXDN Protocol messages
							grp   = (buffer[7U] & 0x20U) == 0x20U;
							srcId = (buffer[8U]  << 8) | buffer[9U];
							dstId = (buffer[10U] << 8) | buffer[11U];

							std::string callsign = lookup->find(srcId);
							LogMessage("Transmission from %s at NXCore to %s%u", callsign.c_str(), grp ? "TG " : "", dstId);

							nxCoreActive = true;
						}
					}

					if (nxCoreActive) {
						watchdogTimer.start();

						for (std::vector<CNXDNRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
							in_addr addr = (*it)->m_address;
							unsigned int prt = (*it)->m_port;
							nxdnNetwork.write(buffer, len, srcId, dstId, grp, addr, prt);
						}

						if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && buffer[5U] == 0x08U) {
							LogMessage("Received end of transmission");
							nxCoreActive = false;
							watchdogTimer.stop();
						}
					}
				}
			}
		}

		unsigned int ms = stopWatch.elapsed();
		stopWatch.start();

		// Remove any repeaters that haven't reported for a while
		for (std::vector<CNXDNRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it)
			(*it)->m_timer.clock(ms);

		for (std::vector<CNXDNRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
			CNXDNRepeater* itRpt = *it;
			if (itRpt->m_timer.hasExpired()) {
				in_addr address      = itRpt->m_address;
				unsigned int port    = itRpt->m_port;
				std::string callsign = itRpt->m_callsign;
				LogMessage("Removing %s (%s:%u) disappeared", callsign.c_str(), ::inet_ntoa(address), port);
				m_repeaters.erase(it);
				delete itRpt;
				break;
			}
		}

		watchdogTimer.clock(ms);
		if (watchdogTimer.isRunning() && watchdogTimer.hasExpired()) {
			LogMessage("Network watchdog has expired");
			watchdogTimer.stop();
			current = NULL;
			nxCoreActive = false;
		}

		dumpTimer.clock(ms);
		if (dumpTimer.hasExpired()) {
			dumpRepeaters();
			dumpTimer.start();
		}

		if (ms < 5U)
			CThread::sleep(5U);
	}

	nxdnNetwork.close();

	closeNXCore();

	lookup->stop();

	::LogFinalise();
}

CNXDNRepeater* CNXDNReflector::findRepeater(const in_addr& address, unsigned int port) const
{
	for (std::vector<CNXDNRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
		if (address.s_addr == (*it)->m_address.s_addr && (*it)->m_port == port)
			return *it;
	}

	return NULL;
}

void CNXDNReflector::dumpRepeaters() const
{
	if (m_repeaters.size() == 0U) {
		LogMessage("No repeaters linked");
		return;
	}

	LogMessage("Currently linked repeaters:");

	for (std::vector<CNXDNRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
		in_addr address      = (*it)->m_address;
		unsigned int port    = (*it)->m_port;
		std::string callsign = (*it)->m_callsign;
		unsigned int timer   = (*it)->m_timer.getTimer();
		unsigned int timeout = (*it)->m_timer.getTimeout();
		LogMessage("    %s (%s:%u) %u/%u", callsign.c_str(), ::inet_ntoa(address), port, timer, timeout);
	}
}

bool CNXDNReflector::openNXCore()
{
	m_nxCoreNetwork = new CNXCoreNetwork(m_conf.getNXCoreAddress(), m_conf.getNXCoreDebug());
	bool ret = m_nxCoreNetwork->open();
	if (!ret) {
		delete m_nxCoreNetwork;
		m_nxCoreNetwork = NULL;
		return false;
	}

	return true;
}

void CNXDNReflector::closeNXCore()
{
	if (m_nxCoreNetwork != NULL) {
		m_nxCoreNetwork->close();
		delete m_nxCoreNetwork;
		m_nxCoreNetwork = NULL;
	}
}
