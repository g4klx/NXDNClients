/*
*   Copyright (C) 2016,2017,2018,2020,2023 by Jonathan Naylor G4KLX
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

#include "KenwoodNetwork.h"
#include "MQTTConnection.h"
#include "IcomNetwork.h"
#include "NXDNGateway.h"
#include "RptNetwork.h"
#include "NXDNLookup.h"
#include "GPSHandler.h"
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
#include <netdb.h>
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

// In Log.cpp
extern CMQTTConnection* m_mqtt;

static CNXDNGateway* gateway = NULL;

const unsigned char NXDN_TYPE_DCALL_HDR = 0x09U;
const unsigned char NXDN_TYPE_DCALL = 0x0BU;
const unsigned char NXDN_TYPE_TX_REL = 0x08U;

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

	gateway = new CNXDNGateway(std::string(iniFile));
	gateway->run();
	delete gateway;

	return 0;
}

CNXDNGateway::CNXDNGateway(const std::string& file) :
m_conf(file),
m_writer(NULL),
m_gps(NULL),
m_voice(NULL),
m_remoteNetwork(NULL),
m_currentTG(0U),
m_currentAddrLen(0U),
m_currentAddr(),
m_currentIsStatic(false),
m_hangTimer(1000U),
m_rfHangTime(0U),
m_reflectors(NULL),
m_staticTGs()
{
	CUDPSocket::startup();
}

CNXDNGateway::~CNXDNGateway()
{
	CUDPSocket::shutdown();
}

void CNXDNGateway::run()
{
	bool ret = m_conf.read();
	if (!ret) {
		::fprintf(stderr, "NXDNGateway: cannot read the .ini file\n");
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
		}
		else if (pid != 0) {
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
	if (m_daemon) {
		::close(STDIN_FILENO);
		::close(STDOUT_FILENO);
		::close(STDERR_FILENO);
	}
#endif
	::LogInitialise(m_conf.getLogDisplayLevel(), m_conf.getLogMQTTLevel());

	std::vector<std::pair<std::string, void (*)(const unsigned char*, unsigned int)>> subscriptions;
	if (m_conf.getRemoteCommandsEnabled())
		subscriptions.push_back(std::make_pair("command", CNXDNGateway::onCommand));

	m_mqtt = new CMQTTConnection(m_conf.getMQTTAddress(), m_conf.getMQTTPort(), m_conf.getMQTTName(), subscriptions, m_conf.getMQTTKeepalive());
	ret = m_mqtt->open();
	if (!ret) {
		delete m_mqtt;
		return;
	}

	createGPS();

	IRptNetwork* localNetwork = NULL;
	std::string protocol = m_conf.getRptProtocol();

	if (protocol == "Kenwood")
		localNetwork = new CKenwoodNetwork(m_conf.getMyPort(), m_conf.getRptAddress(), m_conf.getRptPort(), m_conf.getDebug());
	else
		localNetwork = new CIcomNetwork(m_conf.getMyPort(), m_conf.getRptAddress(), m_conf.getRptPort(), m_conf.getDebug());

	ret = localNetwork->open();
	if (!ret) {
		::LogFinalise();
		return;
	}

	m_remoteNetwork = new CNXDNNetwork(m_conf.getNetworkPort(), m_conf.getCallsign(), m_conf.getNetworkDebug());
	ret = m_remoteNetwork->open();
	if (!ret) {
		delete m_remoteNetwork;
		localNetwork->close();
		delete localNetwork;
		::LogFinalise();
		return;
	}

	m_reflectors = new CReflectors(m_conf.getNetworkHosts1(), m_conf.getNetworkHosts2(), m_conf.getNetworkReloadTime());
	if (m_conf.getNetworkParrotPort() > 0U)
		m_reflectors->setParrot(m_conf.getNetworkParrotAddress(), m_conf.getNetworkParrotPort());
	if (m_conf.getNetworkNXDN2DMRPort() > 0U)
		m_reflectors->setNXDN2DMR(m_conf.getNetworkNXDN2DMRAddress(), m_conf.getNetworkNXDN2DMRPort());
	m_reflectors->load();

	CNXDNLookup* lookup = new CNXDNLookup(m_conf.getLookupName(), m_conf.getLookupTime());
	lookup->read();

	m_rfHangTime  = m_conf.getNetworkRFHangTime();
	unsigned int netHangTime = m_conf.getNetworkNetHangTime();

	CTimer pollTimer(1000U, 5U);
	pollTimer.start();

	CStopWatch stopWatch;
	stopWatch.start();

	if (m_conf.getVoiceEnabled()) {
		m_voice = new CVoice(m_conf.getVoiceDirectory(), m_conf.getVoiceLanguage(), NXDN_VOICE_ID);
		bool ok = m_voice->open();
		if (!ok) {
			delete m_voice;
			m_voice = NULL;
		}
	}

	LogMessage("Starting NXDNGateway-%s", VERSION);

	unsigned short srcId = 0U;
	unsigned short dstTG = 0U;
	bool grp = false;

	std::vector<unsigned short> staticIds = m_conf.getNetworkStatic();

	for (std::vector<unsigned short>::const_iterator it = staticIds.cbegin(); it != staticIds.cend(); ++it) {
		CNXDNReflector* reflector = m_reflectors->find(*it);
		if (reflector != NULL) {
			CStaticTG staticTG;
			staticTG.m_tg      = *it;
			staticTG.m_addr    = reflector->m_addr;
			staticTG.m_addrLen = reflector->m_addrLen;
			m_staticTGs.push_back(staticTG);

			m_remoteNetwork->writePoll(staticTG.m_addr, staticTG.m_addrLen, staticTG.m_tg);
			m_remoteNetwork->writePoll(staticTG.m_addr, staticTG.m_addrLen, staticTG.m_tg);
			m_remoteNetwork->writePoll(staticTG.m_addr, staticTG.m_addrLen, staticTG.m_tg);

			LogMessage("Statically linked to reflector %u", *it);
		}
	}

	for (;;) {
		unsigned char buffer[200U];
		sockaddr_storage addr;
		unsigned int addrLen;

		// From the reflector to the MMDVM
		unsigned int len = m_remoteNetwork->readData(buffer, 200U, addr, addrLen);
		if (len > 0U) {
			// If we're linked and it's from the right place, send it on
			if (m_currentAddrLen > 0U && CUDPSocket::match(m_currentAddr, addr)) {
				// Don't pass reflector control data through to the MMDVM
				if (::memcmp(buffer, "NXDND", 5U) == 0) {
					unsigned short dstTG = 0U;
					dstTG |= (buffer[7U] << 8) & 0xFF00U;
					dstTG |= (buffer[8U] << 0) & 0x00FFU;

					bool grp = (buffer[9U] & 0x01U) == 0x01U;

					if (grp && m_currentTG == dstTG)
						localNetwork->write(buffer + 10U, len - 10U);

					m_hangTimer.start();
				}
			} else if (m_currentTG == 0U) {
				bool poll = false;

				// We weren't really connected yet, but we got a reply from a poll, or some data
				if ((::memcmp(buffer, "NXDND", 5U) == 0) || (poll = (::memcmp(buffer, "NXDNP", 5U) == 0))) {
					// Find the static TG that this audio data/poll belongs to
					for (std::vector<CStaticTG>::const_iterator it = m_staticTGs.cbegin(); it != m_staticTGs.cend(); ++it) {
						if (CUDPSocket::match(addr, (*it).m_addr)) {
							m_currentTG = (*it).m_tg;
							break;
						}
					}

					if (m_currentTG > 0U) {
						m_currentAddr     = addr;
						m_currentAddrLen  = addrLen;
						m_currentIsStatic = true;

						unsigned short dstTG = 0U;
						dstTG |= (buffer[7U] << 8) & 0xFF00U;
						dstTG |= (buffer[8U] << 0) & 0x00FFU;

						bool grp = (buffer[9U] & 0x01U) == 0x01U;

						if (grp && m_currentTG == dstTG && !poll)
							localNetwork->write(buffer + 10U, len - 10U);

						LogMessage("Switched to reflector %u due to network activity", m_currentTG);

						m_hangTimer.setTimeout(netHangTime);
						m_hangTimer.start();
					}
				}
			}
		}

		// From the MMDVM to the reflector or control data
		len = localNetwork->read(buffer);
		if (len > 0U) {
			// Only process the beginning and ending voice blocks here
			if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && (buffer[5U] == 0x01U || buffer[5U] == 0x08U)) {
				grp = (buffer[7U] & 0x20U) == 0x20U;

				srcId  = (buffer[8U] << 8) & 0xFF00U;
				srcId |= (buffer[9U] << 0) & 0x00FFU;

				dstTG  = (buffer[10U] << 8) & 0xFF00U;
				dstTG |= (buffer[11U] << 0) & 0x00FFU;

				if (dstTG != m_currentTG) {
					if (m_currentAddrLen > 0U) {
						std::string callsign = lookup->find(srcId);
						LogMessage("Unlinking from reflector %u by %s", m_currentTG, callsign.c_str());

						if (!m_currentIsStatic) {
							m_remoteNetwork->writeUnlink(m_currentAddr, m_currentAddrLen, m_currentTG);
							m_remoteNetwork->writeUnlink(m_currentAddr, m_currentAddrLen, m_currentTG);
							m_remoteNetwork->writeUnlink(m_currentAddr, m_currentAddrLen, m_currentTG);
						}

						m_hangTimer.stop();
					}

					const CStaticTG* found = NULL;
					for (std::vector<CStaticTG>::const_iterator it = m_staticTGs.cbegin(); it != m_staticTGs.cend(); ++it) {
						if (dstTG == (*it).m_tg) {
							found = &(*it);
							break;
						}
					}

					if (found == NULL) {
						CNXDNReflector* refl = m_reflectors->find(dstTG);
						if (refl != NULL) {
							m_currentTG       = dstTG;
							m_currentAddr     = refl->m_addr;
							m_currentAddrLen  = refl->m_addrLen;
							m_currentIsStatic = false;
						} else {
							m_currentTG       = dstTG;
							m_currentAddrLen  = 0U;
							m_currentIsStatic = false;
						}
					} else {
						m_currentTG       = found->m_tg;
						m_currentAddr     = found->m_addr;
						m_currentAddrLen  = found->m_addrLen;
						m_currentIsStatic = true;
					}

					// Link to the new reflector
					if (m_currentAddrLen > 0U) {
						std::string callsign = lookup->find(srcId);
						LogMessage("Switched to reflector %u due to RF activity from %s", m_currentTG, callsign.c_str());

						if (!m_currentIsStatic) {
							m_remoteNetwork->writePoll(m_currentAddr, m_currentAddrLen, m_currentTG);
							m_remoteNetwork->writePoll(m_currentAddr, m_currentAddrLen, m_currentTG);
							m_remoteNetwork->writePoll(m_currentAddr, m_currentAddrLen, m_currentTG);
						}

						m_hangTimer.setTimeout(m_rfHangTime);
						m_hangTimer.start();
					} else {
						m_hangTimer.stop();
					}

					if (m_voice != NULL) {
						if (m_currentAddrLen == 0U)
							m_voice->unlinked();
						else
							m_voice->linkedTo(m_currentTG);
					}
				}

				// If it's the end of the voice transmission, start the voice prompt
				if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && buffer[5U] == 0x08U) {
					if (m_voice != NULL)
						m_voice->eof();
				}
			}

			if (m_gps != NULL) {
				if ((buffer[0U] & 0xF0U) == 0x90U) {
					switch (buffer[2U] & 0x3FU) {
					case NXDN_TYPE_DCALL_HDR: {
						unsigned short srcId = 0U;
						srcId |= (buffer[5U] << 8) & 0xFF00U;
						srcId |= (buffer[6U] << 0) & 0x00FFU;
						std::string callsign = lookup->find(srcId);
						m_gps->processHeader(callsign);
						}
						break;
					case NXDN_TYPE_DCALL:
						m_gps->processData(buffer + 3U);
						break;
					case NXDN_TYPE_TX_REL:
						m_gps->processEnd();
						break;
					default:
						break;
					}
				}
			}

			// If we're linked and we have a network, send it on
			if (m_currentAddrLen > 0U) {
				m_remoteNetwork->writeData(buffer, len, srcId, dstTG, grp, m_currentAddr, m_currentAddrLen);
				m_hangTimer.start();
			}
		}

		if (m_voice != NULL) {
			unsigned int length = m_voice->read(buffer);
			if (length > 0U)
				localNetwork->write(buffer, length);
		}

		unsigned int ms = stopWatch.elapsed();
		stopWatch.start();

		m_reflectors->clock(ms);

		localNetwork->clock(ms);

		if (m_voice != NULL)
			m_voice->clock(ms);

		m_hangTimer.clock(ms);
		if (m_hangTimer.isRunning() && m_hangTimer.hasExpired()) {
			if (m_currentAddrLen > 0U) {
				LogMessage("Unlinking from %u due to inactivity", m_currentTG);

				if (!m_currentIsStatic) {
					m_remoteNetwork->writeUnlink(m_currentAddr, m_currentAddrLen, m_currentTG);
					m_remoteNetwork->writeUnlink(m_currentAddr, m_currentAddrLen, m_currentTG);
					m_remoteNetwork->writeUnlink(m_currentAddr, m_currentAddrLen, m_currentTG);
				}

				if (m_voice != NULL)
					m_voice->unlinked();

				m_currentAddrLen = 0U;

				m_hangTimer.stop();
			}

			m_currentTG = 0U;
		}

		pollTimer.clock(ms);
		if (pollTimer.isRunning() && pollTimer.hasExpired()) {
			// Poll the static TGs
			for (std::vector<CStaticTG>::const_iterator it = m_staticTGs.cbegin(); it != m_staticTGs.cend(); ++it)
				m_remoteNetwork->writePoll((*it).m_addr, (*it).m_addrLen, (*it).m_tg);

			// Poll the dynamic TG
			if (!m_currentIsStatic && m_currentAddrLen > 0U)
				m_remoteNetwork->writePoll(m_currentAddr, m_currentAddrLen, m_currentTG);

			pollTimer.start();
		}

		if (m_writer != NULL)
			m_writer->clock(ms);

		if (ms < 5U)
			CThread::sleep(5U);
	}

	delete m_voice;

	localNetwork->close();
	delete localNetwork;

	m_remoteNetwork->close();
	delete m_remoteNetwork;

	lookup->stop();

	if (m_gps != NULL) {
		m_writer->close();
		delete m_writer;
		delete m_gps;
	}

	::LogFinalise();
}

void CNXDNGateway::createGPS()
{
	if (!m_conf.getAPRSEnabled())
		return;

	std::string callsign  = m_conf.getCallsign();
	std::string rptSuffix = m_conf.getSuffix();
	std::string suffix    = m_conf.getAPRSSuffix();
	bool debug            = m_conf.getDebug();

	m_writer = new CAPRSWriter(callsign, rptSuffix, debug);

	unsigned int txFrequency = m_conf.getTxFrequency();
	unsigned int rxFrequency = m_conf.getRxFrequency();
	std::string desc         = m_conf.getAPRSDescription();
	std::string symbol  	 = m_conf.getAPRSSymbol();

	m_writer->setInfo(txFrequency, rxFrequency, desc, symbol);

	bool enabled = m_conf.getGPSDEnabled();
	if (enabled) {
	        std::string address = m_conf.getGPSDAddress();
	        std::string port    = m_conf.getGPSDPort();

	        m_writer->setGPSDLocation(address, port);
	} else {
	        float latitude  = m_conf.getLatitude();
                float longitude = m_conf.getLongitude();
                int height      = m_conf.getHeight();

                m_writer->setStaticLocation(latitude, longitude, height);
	}

	bool ret = m_writer->open();
	if (!ret) {
		delete m_writer;
		m_writer = NULL;
		return;
	}

	m_gps = new CGPSHandler(callsign, suffix, m_writer);
}

void CNXDNGateway::writeCommand(const std::string& command)
{
	if (command.substr(0, 9) == "TalkGroup") {
		unsigned int tg = 9999U;
		if (command.length() > 10)
			tg = (unsigned int)std::stoi(command.substr(10));

		if (tg != m_currentTG) {
			if (m_currentAddrLen > 0U) {
				LogMessage("Unlinked from reflector %u by remote command", m_currentTG);

				if (!m_currentIsStatic) {
					m_remoteNetwork->writeUnlink(m_currentAddr, m_currentAddrLen, m_currentTG);
					m_remoteNetwork->writeUnlink(m_currentAddr, m_currentAddrLen, m_currentTG);
					m_remoteNetwork->writeUnlink(m_currentAddr, m_currentAddrLen, m_currentTG);
				}

				m_hangTimer.stop();
			}

			const CStaticTG* found = NULL;
			for (std::vector<CStaticTG>::const_iterator it = m_staticTGs.cbegin(); it != m_staticTGs.cend(); ++it) {
				if (tg == (*it).m_tg) {
					found = &(*it);
					break;
				}
			}

			if (found == NULL) {
				CNXDNReflector* refl = m_reflectors->find(tg);
				if (refl != NULL) {
					m_currentTG       = tg;
					m_currentAddr     = refl->m_addr;
					m_currentAddrLen  = refl->m_addrLen;
					m_currentIsStatic = false;
				} else {
					m_currentTG       = tg;
					m_currentAddrLen  = 0U;
					m_currentIsStatic = false;
				}
			} else {
				m_currentTG       = found->m_tg;
				m_currentAddr     = found->m_addr;
				m_currentAddrLen  = found->m_addrLen;
				m_currentIsStatic = true;
			}

			// Link to the new reflector
			if (m_currentAddrLen > 0U) {
				LogMessage("Switched to reflector %u by remote command", m_currentTG);

				if (!m_currentIsStatic) {
					m_remoteNetwork->writePoll(m_currentAddr, m_currentAddrLen, m_currentTG);
					m_remoteNetwork->writePoll(m_currentAddr, m_currentAddrLen, m_currentTG);
					m_remoteNetwork->writePoll(m_currentAddr, m_currentAddrLen, m_currentTG);
				}

				m_hangTimer.setTimeout(m_rfHangTime);
				m_hangTimer.start();
			} else {
				m_hangTimer.stop();
			}

			if (m_voice != NULL) {
				if (m_currentAddrLen == 0U)
					m_voice->unlinked();
				else
					m_voice->linkedTo(m_currentTG);
			}
		}
	} else if (command.substr(0, 6) == "status") {
		std::string state = std::string("nxdn:") + ((m_currentAddrLen > 0) ? "conn" : "disc");
		m_mqtt->publish("command", state);
	} else if (command.substr(0, 4) == "host") {
		std::string ref;

		if (m_currentAddrLen > 0) {
			char buffer[INET6_ADDRSTRLEN];
			if (::getnameinfo((struct sockaddr*)&m_currentAddr, m_currentAddrLen, buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
				ref = std::string(buffer);
			}
		}

		std::string host = std::string("nxdn:\"") + ((ref.length() == 0) ? "NONE" : ref) + "\"";
		m_mqtt->publish("command", host);
	} else {
		CUtils::dump("Invalid remote command received", (unsigned char*)command.c_str(), command.length());
	}
}

void CNXDNGateway::onCommand(const unsigned char* command, unsigned int length)
{
	assert(gateway != NULL);
	assert(command != NULL);

	gateway->writeCommand(std::string((char*)command, length));
}

