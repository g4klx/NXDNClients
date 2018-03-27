/*
*   Copyright (C) 2016,2017,2018 by Jonathan Naylor G4KLX
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

#include "IcomNetwork.h"
#include "NXDNNetwork.h"
#include "NXDNGateway.h"
#include "NXDNLookup.h"
#include "Reflectors.h"
#include "StopWatch.h"
#include "Version.h"
#include "Thread.h"
#include "Voice.h"
#include "Timer.h"
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
const char* DEFAULT_INI_FILE = "NXDNGateway.ini";
#else
const char* DEFAULT_INI_FILE = "/etc/NXDNGateway.ini";
#endif

#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <ctime>
#include <cstring>

const unsigned short NXDN_VOICE_ID = 9999U;

int main(int argc, char** argv)
{
	const char* iniFile = DEFAULT_INI_FILE;
	if (argc > 1) {
		for (int currentArg = 1; currentArg < argc; ++currentArg) {
			std::string arg = argv[currentArg];
			if ((arg == "-v") || (arg == "--version")) {
				::fprintf(stdout, "NXDNGateway version %s\n", VERSION);
				return 0;
			} else if (arg.substr(0, 1) == "-") {
				::fprintf(stderr, "Usage: NXDNGateway [-v|--version] [filename]\n");
				return 1;
			} else {
				iniFile = argv[currentArg];
			}
		}
	}

	CNXDNGateway* gateway = new CNXDNGateway(std::string(iniFile));
	gateway->run();
	delete gateway;

	return 0;
}

CNXDNGateway::CNXDNGateway(const std::string& file) :
m_conf(file)
{
}

CNXDNGateway::~CNXDNGateway()
{
}

void CNXDNGateway::run()
{
	bool ret = m_conf.read();
	if (!ret) {
		::fprintf(stderr, "NXDNGateway: cannot read the .ini file\n");
		return;
	}

	ret = ::LogInitialise(m_conf.getLogFilePath(), m_conf.getLogFileRoot(), 1U, 1U);
	if (!ret) {
		::fprintf(stderr, "NXDNGateway: unable to open the log file\n");
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

	in_addr rptAddr = CUDPSocket::lookup(m_conf.getRptAddress());
	unsigned int rptPort = m_conf.getRptPort();

	CIcomNetwork localNetwork(m_conf.getMyPort(), m_conf.getRptDebug());
	ret = localNetwork.open();
	if (!ret) {
		::LogFinalise();
		return;
	}

	CNXDNNetwork remoteNetwork(m_conf.getNetworkPort(), m_conf.getCallsign(), m_conf.getNetworkDebug());
	ret = remoteNetwork.open();
	if (!ret) {
		localNetwork.close();
		::LogFinalise();
		return;
	}

	CReflectors reflectors(m_conf.getNetworkHosts1(), m_conf.getNetworkHosts2(), m_conf.getNetworkReloadTime());
	if (m_conf.getNetworkParrotPort() > 0U)
		reflectors.setParrot(m_conf.getNetworkParrotAddress(), m_conf.getNetworkParrotPort());
	reflectors.load();

	CNXDNLookup* lookup = new CNXDNLookup(m_conf.getLookupName(), m_conf.getLookupTime());
	lookup->read();

	CTimer inactivityTimer(1000U, m_conf.getNetworkInactivityTimeout() * 60U);
	CTimer lostTimer(1000U, 120U);
	CTimer pollTimer(1000U, 5U);

	CStopWatch stopWatch;
	stopWatch.start();

	CVoice* voice = NULL;
	if (m_conf.getVoiceEnabled()) {
		voice = new CVoice(m_conf.getVoiceDirectory(), m_conf.getVoiceLanguage(), NXDN_VOICE_ID);
		bool ok = voice->open();
		if (!ok) {
			delete voice;
			voice = NULL;
		}
	}

	LogMessage("Starting NXDNGateway-%s", VERSION);

	unsigned short srcId = 0U;
	unsigned short dstId = 0U;
	bool grp = false;

	unsigned short currentId = 9999U;
	in_addr currentAddr;
	unsigned int currentPort = 0U;

	unsigned short id = m_conf.getNetworkStartup();
	if (id != 9999U) {
		CNXDNReflector* reflector = reflectors.find(id);
		if (reflector != NULL) {
			currentId   = id;
			currentAddr = reflector->m_address;
			currentPort = reflector->m_port;

			inactivityTimer.start();
			pollTimer.start();
			lostTimer.start();

			remoteNetwork.writePoll(currentAddr, currentPort, currentId);
			remoteNetwork.writePoll(currentAddr, currentPort, currentId);
			remoteNetwork.writePoll(currentAddr, currentPort, currentId);

			LogMessage("Linked at startup to reflector %u", currentId);
		}
	}

	for (;;) {
		unsigned char buffer[200U];
		in_addr address;
		unsigned int port;

		// From the reflector to the MMDVM
		unsigned int len = remoteNetwork.readData(buffer, 200U, address, port);
		if (len > 0U) {
			// If we're linked and it's from the right place, send it on
			if (currentId != 9999U && currentAddr.s_addr == address.s_addr && currentPort == port) {
				// Don't pass reflector control data through to the MMDVM
				if (::memcmp(buffer, "NXDND", 5U) == 0) {
					unsigned short dstId = 0U;
					dstId |= (buffer[7U] << 8) & 0xFF00U;
					dstId |= (buffer[8U] << 0) & 0x00FFU;

					bool grp = (buffer[9U] & 0x01U) == 0x01U;

					if (grp && currentId == dstId)
						localNetwork.write(buffer + 10U, len - 10U, rptAddr, rptPort);
				}

				// Any network activity is proof that the reflector is alive
				lostTimer.start();
			}
		}

		// From the MMDVM to the reflector or control data
		len = localNetwork.read(buffer, address, port);
		if (len > 0U) {
			// Only process the beginning and ending blocks here
			if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && (buffer[5U] == 0x01U || buffer[5U] == 0x08U)) {
				grp = (buffer[7U] & 0x20U) == 0x20U;

				srcId  = (buffer[8U] << 8) & 0xFF00U;
				srcId |= (buffer[9U] << 0) & 0x00FFU;

				dstId  = (buffer[10U] << 8) & 0xFF00U;
				dstId |= (buffer[11U] << 0) & 0x00FFU;

				if (dstId != currentId) {
					CNXDNReflector* reflector = NULL;
					if (dstId != 9999U)
						reflector = reflectors.find(dstId);

					// If we're unlinking or changing reflectors, unlink from the current one
					if (dstId == 9999U || reflector != NULL) {
						if (currentId != 9999U) {
							std::string callsign = lookup->find(srcId);
							LogMessage("Unlinked from reflector %u by %s", currentId, callsign.c_str());

							if (voice != NULL && dstId == 9999U)
								voice->unlinked();

							remoteNetwork.writeUnlink(currentAddr, currentPort, currentId);
							remoteNetwork.writeUnlink(currentAddr, currentPort, currentId);
							remoteNetwork.writeUnlink(currentAddr, currentPort, currentId);

							inactivityTimer.stop();
							pollTimer.stop();
							lostTimer.stop();
						}

						currentId = dstId;
					}

					// Link to the new reflector
					if (reflector != NULL) {
						currentId   = dstId;
						currentAddr = reflector->m_address;
						currentPort = reflector->m_port;

						std::string callsign = lookup->find(srcId);
						LogMessage("Linked to reflector %u by %s", currentId, callsign.c_str());

						if (voice != NULL)
							voice->linkedTo(currentId);

						remoteNetwork.writePoll(currentAddr, currentPort, currentId);
						remoteNetwork.writePoll(currentAddr, currentPort, currentId);
						remoteNetwork.writePoll(currentAddr, currentPort, currentId);

						inactivityTimer.start();
						pollTimer.start();
						lostTimer.start();
					}
				}

				// If it's the end of the transmission, start the voice
				if (buffer[5U] == 0x08U) {
					if (voice != NULL)
						voice->eof();
				}
			}

			// If we're linked and we have a network, send it on
			if (currentId != 9999U) {
				remoteNetwork.writeData(buffer, len, srcId, dstId, grp, currentAddr, currentPort);
				inactivityTimer.start();
			}
		}

		if (voice != NULL) {
			unsigned int length = voice->read(buffer);
			if (length > 0U)
				localNetwork.write(buffer, length, rptAddr, rptPort);
		}

		unsigned int ms = stopWatch.elapsed();
		stopWatch.start();

		reflectors.clock(ms);

		if (voice != NULL)
			voice->clock(ms);

		inactivityTimer.clock(ms);
		if (inactivityTimer.isRunning() && inactivityTimer.hasExpired()) {
			if (currentId != 9999U) {
				LogMessage("Unlinking from %u due to inactivity", currentId);

				remoteNetwork.writeUnlink(currentAddr, currentPort, currentId);
				remoteNetwork.writeUnlink(currentAddr, currentPort, currentId);
				remoteNetwork.writeUnlink(currentAddr, currentPort, currentId);

				if (voice != NULL)
					voice->unlinked();
				currentId = 9999U;

				pollTimer.stop();
				lostTimer.stop();
			}

			inactivityTimer.stop();
		}

		pollTimer.clock(ms);
		if (pollTimer.isRunning() && pollTimer.hasExpired()) {
			if (currentId != 9999U)
				remoteNetwork.writePoll(currentAddr, currentPort, currentId);
			pollTimer.start();
		}

		lostTimer.clock(ms);
		if (lostTimer.isRunning() && lostTimer.hasExpired()) {
			if (currentId != 9999U) {
				LogWarning("No response from %u, unlinking", currentId);
				currentId = 9999U;
			}

			inactivityTimer.stop();
			lostTimer.stop();
		}

		if (ms < 5U)
			CThread::sleep(5U);
	}

	delete voice;

	localNetwork.close();

	remoteNetwork.close();

	lookup->stop();

	::LogFinalise();
}
