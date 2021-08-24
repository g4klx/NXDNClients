/*
*   Copyright (C) 2016,2018,2020,2021 by Jonathan Naylor G4KLX
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
m_icomNetwork(NULL),
m_kenwoodNetwork(NULL),
m_repeaters()
{
	CUDPSocket::startup();
}

CNXDNReflector::~CNXDNReflector()
{
	CUDPSocket::shutdown();
}

void CNXDNReflector::run()
{
	bool ret = m_conf.read();
	if (!ret) {
		::fprintf(stderr, "NXDNReflector: cannot read the .ini file\n");
		return;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	bool m_daemon = m_conf.getDaemon();
	if (m_daemon) {
		// Create new process
		pid_t pid = ::fork();
		if (pid == -1) {
			::fprintf(stderr, "Couldn't fork() , exiting\n");
			return;
		} else if (pid != 0) {
			exit(EXIT_SUCCESS);
		}

		// Create new session and process group
		if (::setsid() == -1) {
			::fprintf(stderr, "Couldn't setsid(), exiting\n");
			return;
		}

		// Set the working directory to the root directory
		if (::chdir("/") == -1) {
			::fprintf(stderr, "Couldn't cd /, exiting\n");
			return;
		}

		// If we are currently root...
		if (getuid() == 0) {
			struct passwd* user = ::getpwnam("mmdvm");
			if (user == NULL) {
				::fprintf(stderr, "Could not get the mmdvm user, exiting\n");
				return;
			}

			uid_t mmdvm_uid = user->pw_uid;
			gid_t mmdvm_gid = user->pw_gid;

			// Set user and group ID's to mmdvm:mmdvm
			if (setgid(mmdvm_gid) != 0) {
				::fprintf(stderr, "Could not set mmdvm GID, exiting\n");
				return;
			}

			if (setuid(mmdvm_uid) != 0) {
				::fprintf(stderr, "Could not set mmdvm UID, exiting\n");
				return;
			}

			// Double check it worked (AKA Paranoia) 
			if (setuid(0) != -1) {
				::fprintf(stderr, "It's possible to regain root - something is wrong!, exiting\n");
				return;
			}
		}
	}
#endif

#if !defined(_WIN32) && !defined(_WIN64)
        ret = ::LogInitialise(m_daemon, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate());
#else
        ret = ::LogInitialise(false, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate());
#endif
	if (!ret) {
		::fprintf(stderr, "NXDNReflector: unable to open the log file\n");
		return;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	if (m_daemon) {
		::close(STDIN_FILENO);
		::close(STDOUT_FILENO);
		::close(STDERR_FILENO);
	}
#endif

	unsigned short tg = m_conf.getTG();

	CNXDNNetwork nxdnNetwork(m_conf.getNetworkPort(), m_conf.getNetworkDebug());
	ret = nxdnNetwork.open();
	if (!ret) {
		::LogFinalise();
		return;
	}

	bool icomEnabled = m_conf.getIcomEnabled();

	unsigned short icomTGEnable = 0U;
	unsigned short icomTGDisable = 0U;

	if (icomEnabled) {
		ret = openIcomNetwork();
		if (!ret) {
			nxdnNetwork.close();
			::LogFinalise();
			return;
		}

		icomTGEnable  = m_conf.getIcomTGEnable();
		icomTGDisable = m_conf.getIcomTGDisable();
	}

	bool kenwoodEnabled = m_conf.getKenwoodEnabled();

	unsigned short kenwoodTGEnable = 0U;
	unsigned short kenwoodTGDisable = 0U;

	if (kenwoodEnabled) {
		ret = openKenwoodNetwork();
		if (!ret) {
			nxdnNetwork.close();
			::LogFinalise();
			return;
		}

		kenwoodTGEnable  = m_conf.getKenwoodTGEnable();
		kenwoodTGDisable = m_conf.getKenwoodTGDisable();
	}

	CNXDNLookup* lookup = new CNXDNLookup(m_conf.getLookupName(), m_conf.getLookupTime());
	lookup->read();

	CStopWatch stopWatch;
	stopWatch.start();

	CTimer dumpTimer(1000U, 120U);
	dumpTimer.start();

	LogMessage("Starting NXDNReflector-%s", VERSION);

	enum {
		ACTIVE_NONE,
		ACTIVE_NXDN,
		ACTIVE_ICOM,
		ACTIVE_KENWOOD
	} active = ACTIVE_NONE;

	CNXDNRepeater* current = NULL;

	unsigned short srcId = 0U;
	unsigned short dstId = 0U;
	bool grp = false;

	CTimer watchdogTimer(1000U, 0U, 1500U);

	for (;;) {
		unsigned char buffer[200U];
		sockaddr_storage address;
		unsigned int addressLen;

		unsigned int len = nxdnNetwork.read(buffer, 200U, address, addressLen);
		if (len > 0U) {
			CNXDNRepeater* rpt = findRepeater(address);

			if (::memcmp(buffer, "NXDNP", 5U) == 0 && len == 17U) {
				unsigned short id = (buffer[15U] << 8) | buffer[16U];
				if (id == tg) {
					if (rpt == NULL) {
						rpt = new CNXDNRepeater;
						rpt->m_timer.start();
						::memcpy(&rpt->m_addr, &address, sizeof(struct sockaddr_storage));
						rpt->m_addrLen  = addressLen;
						rpt->m_callsign = std::string((char*)(buffer + 5U), 10U);
						m_repeaters.push_back(rpt);

						char buff[80U];
						LogMessage("Adding %s (%s)", rpt->m_callsign.c_str(), CUDPSocket::display(address, buff, 80U));
					} else {
						rpt->m_timer.start();
					}

					// Return the poll
					nxdnNetwork.write(buffer, len, address, addressLen);
				}
			} else if (::memcmp(buffer, "NXDNU", 5U) == 0 && len == 17U) {
				unsigned short id = (buffer[15U] << 8) | buffer[16U];
				if (id == tg) {
					if (rpt != NULL) {
						std::string callsign = std::string((char*)(buffer + 5U), 10U);

						char buff[80U];
						LogMessage("Removing %s (%s) unlinked", callsign.c_str(), CUDPSocket::display(address, buff, 80U));

						for (std::vector<CNXDNRepeater*>::iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
							if (*it == rpt) {
								m_repeaters.erase(it);
								break;
							}
						}

						delete rpt;
					}
				}
			} else if (::memcmp(buffer, "NXDND", 5U) == 0 && len == 43U) {
				if (rpt != NULL) {
					unsigned short srcId = (buffer[5U] << 8) | buffer[6U];
					unsigned short dstId = (buffer[7U] << 8) | buffer[8U];
					bool grp = (buffer[9U] & 0x01U) == 0x01U;

					if (icomEnabled && icomTGEnable != 0U && grp && dstId == icomTGEnable) {
						if (m_icomNetwork == NULL) {
							std::string callsign = lookup->find(srcId);
							LogMessage("Icom Network link enabled by %s at %s", callsign.c_str(), current->m_callsign.c_str());
							bool ok = openIcomNetwork();
							if (!ok)
								LogWarning("Unable to open the Icom Network link");
						}
					}

					if (kenwoodEnabled && kenwoodTGEnable != 0U && grp && dstId == kenwoodTGEnable) {
						if (m_kenwoodNetwork == NULL) {
							std::string callsign = lookup->find(srcId);
							LogMessage("Kenwood Network link enabled by %s at %s", callsign.c_str(), current->m_callsign.c_str());
							bool ok = openKenwoodNetwork();
							if (!ok)
								LogWarning("Unable to open the Kenwood Network link");
						}
					}

					if (icomEnabled && icomTGDisable != 0U && grp && dstId == icomTGDisable) {
						if (m_icomNetwork != NULL) {
							std::string callsign = lookup->find(srcId);
							LogMessage("Icom Network link disabled by %s at %s", callsign.c_str(), current->m_callsign.c_str());
							closeIcomNetwork();
						}
					}

					if (kenwoodEnabled && kenwoodTGDisable != 0U && grp && dstId == kenwoodTGDisable) {
						if (m_kenwoodNetwork != NULL) {
							std::string callsign = lookup->find(srcId);
							LogMessage("Kenwood Network link disabled by %s at %s", callsign.c_str(), current->m_callsign.c_str());
							closeKenwoodNetwork();
						}
					}

					if (grp && dstId == tg) {
						rpt->m_timer.start();

						if (current == NULL && active == ACTIVE_NONE) {
							current = rpt;

							std::string callsign = lookup->find(srcId);
							LogMessage("Transmission from %s at %s to %s%u", callsign.c_str(), current->m_callsign.c_str(), grp ? "TG " : "", dstId);

							active = ACTIVE_NXDN;
						}

						if (active == ACTIVE_NXDN) {
							watchdogTimer.start();

							for (std::vector<CNXDNRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
								if (!CUDPSocket::match((*it)->m_addr, address))
									nxdnNetwork.write(buffer, len, (*it)->m_addr, (*it)->m_addrLen);
							}

							if (m_icomNetwork != NULL)
								m_icomNetwork->write(buffer, len);

							if (m_kenwoodNetwork != NULL)
								m_kenwoodNetwork->write(buffer, len);

							if ((buffer[9U] & 0x08U) == 0x08U) {
								LogMessage("Received end of transmission");
								current = NULL;
								active = ACTIVE_NONE;
								watchdogTimer.stop();
							}
						}
					}
				} else {
					LogMessage("Data received from an unknown source");
					CUtils::dump(2U, "Data", buffer, len);
				}
			}
		}

		if (m_icomNetwork != NULL) {
			len = m_icomNetwork->read(buffer);
			if (len > 0U) {
				if (current == NULL) {
					if (active == ACTIVE_NONE) {
						if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && buffer[5U] == 0x01U) {
							bool           tempGrp   = (buffer[7U] & 0x20U) == 0x20U;
							unsigned short tempSrcId = (buffer[8U]  << 8) | buffer[9U];
							unsigned short tempDstId = (buffer[10U] << 8) | buffer[11U];

							if (tempGrp && tempDstId == tg) {
								// Save the grp, src and dest for use in the NXDN Protocol messages
								grp   = tempGrp;
								srcId = tempSrcId;
								dstId = tempDstId;

								std::string callsign = lookup->find(srcId);
								LogMessage("Transmission from %s on Icom Network to %s%u", callsign.c_str(), grp ? "TG " : "", dstId);

								active = ACTIVE_ICOM;
							}
						}
						if ((buffer[0U] & 0xF0U) == 0x90U && buffer[2U] == 0x09U) {
							bool           tempGrp   = (buffer[4U] & 0x20U) == 0x20U;
							unsigned short tempSrcId = (buffer[5U] << 8) | buffer[6U];
							unsigned short tempDstId = (buffer[7U] << 8) | buffer[8U];

							if (tempGrp && tempDstId == tg) {
								// Save the grp, src and dest for use in the NXDN Protocol messages
								grp   = tempGrp;
								srcId = tempSrcId;
								dstId = tempDstId;

								std::string callsign = lookup->find(srcId);
								LogMessage("Transmission from %s on Icom Network to %s%u", callsign.c_str(), grp ? "TG " : "", dstId);

								active = ACTIVE_ICOM;
							}
						}
					}

					if (active == ACTIVE_ICOM) {
						watchdogTimer.start();

						for (std::vector<CNXDNRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it)
							nxdnNetwork.write(buffer, len, srcId, dstId, grp, (*it)->m_addr, (*it)->m_addrLen);

						if (m_kenwoodNetwork != NULL)
							m_kenwoodNetwork->write(buffer, len);

						if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && buffer[5U] == 0x08U) {
							LogMessage("Received end of transmission");
							active = ACTIVE_NONE;
							watchdogTimer.stop();
						}
						if ((buffer[0U] & 0xF0U) == 0x90U && buffer[2U] == 0x08U) {
							LogMessage("Received end of transmission");
							active = ACTIVE_NONE;
							watchdogTimer.stop();
						}
					}
				}
			}
		}

		if (m_kenwoodNetwork != NULL) {
			len = m_kenwoodNetwork->read(buffer);
			if (len > 0U) {
				if (current == NULL) {
					if (active == ACTIVE_NONE) {
						if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && buffer[5U] == 0x01U) {
							bool           tempGrp   = (buffer[7U] & 0x20U) == 0x20U;
							unsigned short tempSrcId = (buffer[8U] << 8) | buffer[9U];
							unsigned short tempDstId = (buffer[10U] << 8) | buffer[11U];

							if (tempGrp && tempDstId == tg) {
								// Save the grp, src and dest for use in the NXDN Protocol messages
								grp   = tempGrp;
								srcId = tempSrcId;
								dstId = tempDstId;

								std::string callsign = lookup->find(srcId);
								LogMessage("Transmission from %s on Kenwood Network to %s%u", callsign.c_str(), grp ? "TG " : "", dstId);

								active = ACTIVE_KENWOOD;
							}
						}
						if ((buffer[0U] & 0xF0U) == 0x90U && buffer[2U] == 0x09U) {
							bool           tempGrp   = (buffer[4U] & 0x20U) == 0x20U;
							unsigned short tempSrcId = (buffer[5U] << 8) | buffer[6U];
							unsigned short tempDstId = (buffer[7U] << 8) | buffer[8U];

							if (tempGrp && tempDstId == tg) {
								// Save the grp, src and dest for use in the NXDN Protocol messages
								grp   = tempGrp;
								srcId = tempSrcId;
								dstId = tempDstId;

								std::string callsign = lookup->find(srcId);
								LogMessage("Transmission from %s on Kenwood Network to %s%u", callsign.c_str(), grp ? "TG " : "", dstId);

								active = ACTIVE_KENWOOD;
							}
						}
					}

					if (active == ACTIVE_KENWOOD) {
						watchdogTimer.start();

						for (std::vector<CNXDNRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it)
							nxdnNetwork.write(buffer, len, srcId, dstId, grp, (*it)->m_addr, (*it)->m_addrLen);

						if (m_icomNetwork != NULL)
							m_icomNetwork->write(buffer, len);

						if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && buffer[5U] == 0x08U) {
							LogMessage("Received end of transmission");
							active = ACTIVE_NONE;
							watchdogTimer.stop();
						}
						if ((buffer[0U] & 0xF0U) == 0x90U && buffer[2U] == 0x08U) {
							LogMessage("Received end of transmission");
							active = ACTIVE_NONE;
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
			if ((*it)->m_timer.hasExpired()) {
				char buff[80U];
				LogMessage("Removing %s (%s) disappeared", (*it)->m_callsign.c_str(),
														   CUDPSocket::display((*it)->m_addr, buff, 80U));

				delete *it;
				m_repeaters.erase(it);
				break;
			}
		}

		watchdogTimer.clock(ms);
		if (watchdogTimer.isRunning() && watchdogTimer.hasExpired()) {
			LogMessage("Network watchdog has expired");
			watchdogTimer.stop();
			current = NULL;
			active = ACTIVE_NONE;
		}

		dumpTimer.clock(ms);
		if (dumpTimer.hasExpired()) {
			dumpRepeaters();
			dumpTimer.start();
		}

		if (m_icomNetwork != NULL)
			m_icomNetwork->clock(ms);

		if (m_kenwoodNetwork != NULL)
			m_kenwoodNetwork->clock(ms);

		if (ms < 5U)
			CThread::sleep(5U);
	}

	nxdnNetwork.close();

	closeIcomNetwork();

	closeKenwoodNetwork();

	lookup->stop();

	::LogFinalise();
}

CNXDNRepeater* CNXDNReflector::findRepeater(const sockaddr_storage& addr) const
{
	for (std::vector<CNXDNRepeater*>::const_iterator it = m_repeaters.begin(); it != m_repeaters.end(); ++it) {
		if (CUDPSocket::match(addr, (*it)->m_addr))
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
		char buffer[80U];
		LogMessage("    %s: %s %u/%u", (*it)->m_callsign.c_str(),
									   CUDPSocket::display((*it)->m_addr, buffer, 80U), 
									   (*it)->m_timer.getTimer(),
									   (*it)->m_timer.getTimeout());
	}
}

bool CNXDNReflector::openIcomNetwork()
{
	m_icomNetwork = new CIcomNetwork(m_conf.getIcomAddress(), m_conf.getIcomDebug());
	bool ret = m_icomNetwork->open();
	if (!ret) {
		delete m_icomNetwork;
		m_icomNetwork = NULL;
		return false;
	}

	return true;
}

bool CNXDNReflector::openKenwoodNetwork()
{
	m_kenwoodNetwork = new CKenwoodNetwork(m_conf.getKenwoodAddress(), m_conf.getKenwoodDebug());
	bool ret = m_kenwoodNetwork->open();
	if (!ret) {
		delete m_kenwoodNetwork;
		m_kenwoodNetwork = NULL;
		return false;
	}

	return true;
}

void CNXDNReflector::closeIcomNetwork()
{
	if (m_icomNetwork != NULL) {
		m_icomNetwork->close();
		delete m_icomNetwork;
		m_icomNetwork = NULL;
	}
}

void CNXDNReflector::closeKenwoodNetwork()
{
	if (m_kenwoodNetwork != NULL) {
		m_kenwoodNetwork->close();
		delete m_kenwoodNetwork;
		m_kenwoodNetwork = NULL;
	}
}
