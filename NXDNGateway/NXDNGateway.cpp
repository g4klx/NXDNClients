/*
*   Copyright (C) 2016,2017,2018,2020,2024,2025 by Jonathan Naylor G4KLX
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
#include "IcomNetwork.h"
#include "NXDNNetwork.h"
#include "NXDNGateway.h"
#include "RptNetwork.h"
#include "NXDNLookup.h"
#include "Reflectors.h"
#include "GPSHandler.h"
#include "StopWatch.h"
#include "Version.h"
#include "Thread.h"
#include "Timer.h"
#include "Utils.h"
#include "Log.h"
#include "GitVersion.h"

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

static bool m_killed = false;
static int  m_signal = 0;

#if !defined(_WIN32) && !defined(_WIN64)
static void sigHandler(int signum)
{
	m_killed = true;
	m_signal = signum;
}
#endif

const unsigned char NXDN_TYPE_DCALL_HDR = 0x09U;
const unsigned char NXDN_TYPE_DCALL = 0x0BU;
const unsigned char NXDN_TYPE_TX_REL = 0x08U;

const unsigned short NXDN_VOICE_ID = 9999U;

class CStaticTG {
public:
	unsigned short   m_tg;
	sockaddr_storage m_addr;
	unsigned int     m_addrLen;
};

int main(int argc, char** argv)
{
	const char* iniFile = DEFAULT_INI_FILE;
	if (argc > 1) {
		for (int currentArg = 1; currentArg < argc; ++currentArg) {
			std::string arg = argv[currentArg];
			if ((arg == "-v") || (arg == "--version")) {
				::fprintf(stdout, "NXDNGateway version %s git #%.7s\n", VERSION, gitversion);
				return 0;
			} else if (arg.substr(0, 1) == "-") {
				::fprintf(stderr, "Usage: NXDNGateway [-v|--version] [filename]\n");
				return 1;
			} else {
				iniFile = argv[currentArg];
			}
		}
	}


#if !defined(_WIN32) && !defined(_WIN64)
	::signal(SIGINT,  sigHandler);
	::signal(SIGTERM, sigHandler);
	::signal(SIGHUP,  sigHandler);
#endif

	int ret = 0;

	do {
		m_signal = 0;
		m_killed = false;

		CNXDNGateway* gateway = new CNXDNGateway(std::string(iniFile));
		ret = gateway->run();

		delete gateway;

		switch (m_signal) {
			case 0:
				break;
			case 2:
				::LogInfo("NXDNGateway-%s exited on receipt of SIGINT", VERSION);
				break;
			case 15:
				::LogInfo("NXDNGateway-%s exited on receipt of SIGTERM", VERSION);
				break;
			case 1:
				::LogInfo("NXDNGateway-%s is restarting on receipt of SIGHUP", VERSION);
				break;
			default:
				::LogInfo("NXDNGateway-%s exited on receipt of an unknown signal", VERSION);
				break;
		}
	} while (m_signal == 1);

	::LogFinalise();

	return ret;
}

CNXDNGateway::CNXDNGateway(const std::string& file) :
m_conf(file),
m_writer(nullptr),
m_gps(nullptr),
m_voice(nullptr)
{
	CUDPSocket::startup();
}

CNXDNGateway::~CNXDNGateway()
{
	CUDPSocket::shutdown();
}

int CNXDNGateway::run()
{
	bool ret = m_conf.read();
	if (!ret) {
		::fprintf(stderr, "NXDNGateway: cannot read the .ini file\n");
		return 1;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	bool m_daemon = m_conf.getDaemon();
	if (m_daemon) {
		// Create new process
		pid_t pid = ::fork();
		if (pid == -1) {
			::fprintf(stderr, "Couldn't fork() , exiting\n");
			return 1;
		}
		else if (pid != 0) {
			exit(EXIT_SUCCESS);
		}

		// Create new session and process group
		if (::setsid() == -1) {
			::fprintf(stderr, "Couldn't setsid(), exiting\n");
			return 1;
		}

		// Set the working directory to the root directory
		if (::chdir("/") == -1) {
			::fprintf(stderr, "Couldn't cd /, exiting\n");
			return 1;
		}

		// If we are currently root...
		if (getuid() == 0) {
			struct passwd* user = ::getpwnam("mmdvm");
			if (user == nullptr) {
				::fprintf(stderr, "Could not get the mmdvm user, exiting\n");
				return 1;
			}

			uid_t mmdvm_uid = user->pw_uid;
			gid_t mmdvm_gid = user->pw_gid;

			// Set user and group ID's to mmdvm:mmdvm
			if (setgid(mmdvm_gid) != 0) {
				::fprintf(stderr, "Could not set mmdvm GID, exiting\n");
				return 1;
			}

			if (setuid(mmdvm_uid) != 0) {
				::fprintf(stderr, "Could not set mmdvm UID, exiting\n");
				return 1;
			}

			// Double check it worked (AKA Paranoia) 
			if (setuid(0) != -1) {
				::fprintf(stderr, "It's possible to regain root - something is wrong!, exiting\n");
				return 1;
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
		::fprintf(stderr, "NXDNGateway: unable to open the log file\n");
		return 1;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	if (m_daemon) {
		::close(STDIN_FILENO);
		::close(STDOUT_FILENO);
		::close(STDERR_FILENO);
	}
#endif

	createGPS();

	IRptNetwork* localNetwork = nullptr;
	std::string protocol = m_conf.getRptProtocol();

	if (protocol == "Kenwood")
		localNetwork = new CKenwoodNetwork(m_conf.getMyPort(), m_conf.getRptAddress(), m_conf.getRptPort(), m_conf.getDebug());
	else
		localNetwork = new CIcomNetwork(m_conf.getMyPort(), m_conf.getRptAddress(), m_conf.getRptPort(), m_conf.getDebug());

	ret = localNetwork->open();
	if (!ret)
		return 1;

	CNXDNNetwork remoteNetwork(m_conf.getNetworkPort(), m_conf.getCallsign(), m_conf.getNetworkDebug());
	ret = remoteNetwork.open();
	if (!ret) {
		localNetwork->close();
		delete localNetwork;
		return 1;
	}

	CUDPSocket* remoteSocket = nullptr;
	if (m_conf.getRemoteCommandsEnabled()) {
		remoteSocket = new CUDPSocket(m_conf.getRemoteCommandsPort());
		ret = remoteSocket->open();
		if (!ret) {
			delete remoteSocket;
			remoteSocket = nullptr;
		}
	}

	CReflectors reflectors(m_conf.getNetworkHosts1(), m_conf.getNetworkHosts2(), m_conf.getNetworkReloadTime());
	if (m_conf.getNetworkParrotPort() > 0U)
		reflectors.setParrot(m_conf.getNetworkParrotAddress(), m_conf.getNetworkParrotPort());
	if (m_conf.getNetworkNXDN2DMRPort() > 0U)
		reflectors.setNXDN2DMR(m_conf.getNetworkNXDN2DMRAddress(), m_conf.getNetworkNXDN2DMRPort());
	reflectors.load();

	CNXDNLookup* lookup = new CNXDNLookup(m_conf.getLookupName(), m_conf.getLookupTime());
	lookup->read();

	unsigned int rfHangTime  = m_conf.getNetworkRFHangTime();
	unsigned int netHangTime = m_conf.getNetworkNetHangTime();

	CTimer hangTimer(1000U);

	CTimer pollTimer(1000U, 5U);
	pollTimer.start();

	CStopWatch stopWatch;
	stopWatch.start();

	if (m_conf.getVoiceEnabled()) {
		m_voice = new CVoice(m_conf.getVoiceDirectory(), m_conf.getVoiceLanguage(), NXDN_VOICE_ID);
		bool ok = m_voice->open();
		if (!ok) {
			delete m_voice;
			m_voice = nullptr;
		}
	}

	LogMessage("Starting NXDNGateway-%s", VERSION);

	unsigned short srcId = 0U;
	unsigned short dstTG = 0U;
	bool grp = false;

	bool currentIsStatic = false;
	CNXDNReflector currentTG;

	std::vector<unsigned short> staticIds = m_conf.getNetworkStatic();

	std::vector<CNXDNReflector> staticTGs;
	for (const auto& it : staticIds) {
		CNXDNReflector* reflector = reflectors.find(it);
		if (reflector != nullptr) {
			staticTGs.push_back(*reflector);

			remoteNetwork.writePoll(*reflector);
			remoteNetwork.writePoll(*reflector);
			remoteNetwork.writePoll(*reflector);

			LogMessage("Statically linked to reflector %u", it);
		}
	}

	while (!m_killed) {
		unsigned char buffer[200U];
		sockaddr_storage addr;
		unsigned int addrLen;

		// From the reflector to the MMDVM
		unsigned int len = remoteNetwork.readData(buffer, 200U, addr, addrLen);
		while (len > 0U) {
			// If we're linked and it's from the right place, send it on
			if (currentTG.isUsed() && CNXDNNetwork::match(addr, currentTG)) {
				// Don't pass reflector control data through to the MMDVM
				if (::memcmp(buffer, "NXDND", 5U) == 0) {
					unsigned short dstTG = 0U;
					dstTG |= (buffer[7U] << 8) & 0xFF00U;
					dstTG |= (buffer[8U] << 0) & 0x00FFU;

					bool grp = (buffer[9U] & 0x01U) == 0x01U;

					if (grp && currentTG.m_id == dstTG) {
						if (!isVoiceBusy())
							localNetwork->write(buffer + 10U, len - 10U);
					}

					hangTimer.start();
				}
			} else if (currentTG.isEmpty()) {
				bool poll = false;

				// We weren't really connected yet, but we got a reply from a poll, or some data
				if ((::memcmp(buffer, "NXDND", 5U) == 0) || (poll = (::memcmp(buffer, "NXDNP", 5U) == 0))) {
					// Find the static TG that this audio data/poll belongs to
					for (const auto& it : staticTGs) {
						if (CNXDNNetwork::match(addr, it)) {
							currentTG = it;
							break;
						}
					}

					if (currentTG.isUsed()) {
						currentIsStatic = true;

						unsigned short dstTG = 0U;
						dstTG |= (buffer[7U] << 8) & 0xFF00U;
						dstTG |= (buffer[8U] << 0) & 0x00FFU;

						bool grp = (buffer[9U] & 0x01U) == 0x01U;

						if (grp && (currentTG.m_id == dstTG) && !poll) {
							if (!isVoiceBusy())
								localNetwork->write(buffer + 10U, len - 10U);
						}

						LogMessage("Switched to reflector %u due to network activity", currentTG.m_id);

						hangTimer.setTimeout(netHangTime);
						hangTimer.start();
					}
				}
			}

			len = remoteNetwork.readData(buffer, 200U, addr, addrLen);
		}

		// From the MMDVM to the reflector or control data
		len = localNetwork->read(buffer);
		while (len > 0U) {
			// Only process the beginning and ending voice blocks here
			if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && (buffer[5U] == 0x01U || buffer[5U] == 0x08U)) {
				grp = (buffer[7U] & 0x20U) == 0x20U;

				srcId  = (buffer[8U] << 8) & 0xFF00U;
				srcId |= (buffer[9U] << 0) & 0x00FFU;

				dstTG  = (buffer[10U] << 8) & 0xFF00U;
				dstTG |= (buffer[11U] << 0) & 0x00FFU;

				if (dstTG != currentTG.m_id) {
					if (currentTG.isUsed()) {
						std::string callsign = lookup->find(srcId);
						LogMessage("Unlinking from reflector %u by %s", currentTG.m_id, callsign.c_str());

						if (!currentIsStatic) {
							remoteNetwork.writeUnlink(currentTG);
							remoteNetwork.writeUnlink(currentTG);
							remoteNetwork.writeUnlink(currentTG);
						}

						hangTimer.stop();
					}

					CNXDNReflector found;
					for (const auto& it : staticTGs) {
						if (dstTG == it.m_id) {
							found = it;
							break;
						}
					}

					if (found.isEmpty()) {
						CNXDNReflector* refl = reflectors.find(dstTG);
						if (refl != nullptr) {
							currentTG       = *refl;
							currentIsStatic = false;
						} else {
							currentTG.reset();
							currentIsStatic = false;
						}
					} else {
						currentTG       = found;
						currentIsStatic = true;
					}

					// Link to the new reflector
					if (currentTG.isUsed()) {
						std::string callsign = lookup->find(srcId);
						LogMessage("Switched to reflector %u due to RF activity from %s", currentTG.m_id, callsign.c_str());

						if (!currentIsStatic) {
							remoteNetwork.writePoll(currentTG);
							remoteNetwork.writePoll(currentTG);
							remoteNetwork.writePoll(currentTG);
						}

						hangTimer.setTimeout(rfHangTime);
						hangTimer.start();
					} else {
						hangTimer.stop();
					}

					if (m_voice != nullptr) {
						if (currentTG.isEmpty())
							m_voice->unlinked();
						else
							m_voice->linkedTo(currentTG.m_id);
					}
				}

				// If it's the end of the voice transmission, start the voice prompt
				if ((buffer[0U] == 0x81U || buffer[0U] == 0x83U) && buffer[5U] == 0x08U) {
					if (m_voice != nullptr)
						m_voice->eof();
				}
			}

			if (m_gps != nullptr) {
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
			if (currentTG.isUsed()) {
				remoteNetwork.writeData(buffer, len, srcId, dstTG, grp, currentTG);
				hangTimer.start();
			}

			len = localNetwork->read(buffer);
		}

		if (m_voice != nullptr) {
			unsigned int length = m_voice->read(buffer);
			if (length > 0U)
				localNetwork->write(buffer, length);
		}

		if (remoteSocket != nullptr) {
			sockaddr_storage addr;
			unsigned int addrLen;
			int res = remoteSocket->read(buffer, 200U, addr, addrLen);
			if (res > 0) {
				buffer[res] = '\0';
				if (::memcmp(buffer + 0U, "TalkGroup", 9U) == 0) {
					unsigned int tg = ((strlen((char*)buffer + 0U) > 10) ? (unsigned int)::atoi((char*)(buffer + 10U)) : 9999);

					if (tg != currentTG.m_id) {
						if (currentTG.isUsed()) {
							LogMessage("Unlinked from reflector %u by remote command", currentTG.m_id);

							if (!currentIsStatic) {
								remoteNetwork.writeUnlink(currentTG);
								remoteNetwork.writeUnlink(currentTG);
								remoteNetwork.writeUnlink(currentTG);
							}

							hangTimer.stop();
						}

						CNXDNReflector found;
						for (const auto& it : staticTGs) {
							if (tg == it.m_id) {
								found = it;
								break;
							}
						}

						if (found.isEmpty()) {
							CNXDNReflector* refl = reflectors.find(tg);
							if (refl != nullptr) {
								currentTG       = *refl;
								currentIsStatic = false;
							} else {
								currentTG.reset();
								currentIsStatic = false;
							}
						} else {
							currentTG = found;
							currentIsStatic = true;
						}

						// Link to the new reflector
						if (currentTG.isUsed()) {
							LogMessage("Switched to reflector %u by remote command", currentTG.m_id);

							if (!currentIsStatic) {
								remoteNetwork.writePoll(currentTG);
								remoteNetwork.writePoll(currentTG);
								remoteNetwork.writePoll(currentTG);
							}

							hangTimer.setTimeout(rfHangTime);
							hangTimer.start();
						} else {
							hangTimer.stop();
						}

						if (m_voice != nullptr) {
							if (currentTG.isEmpty())
								m_voice->unlinked();
							else
								m_voice->linkedTo(currentTG.m_id);
						}
					}
				} else if (::memcmp(buffer + 0U, "status", 6U) == 0) {
					std::string state = std::string("nxdn:") + (currentTG.isUsed() ? "conn" : "disc");
					remoteSocket->write((unsigned char*)state.c_str(), (unsigned int)state.length(), addr, addrLen);
				} else if (::memcmp(buffer + 0U, "host", 4U) == 0) {
					std::string host = "nxdn:\"NONE\"";

					if (currentTG.isUsed()) {
						if (remoteNetwork.hasIPv6() && currentTG.hasIPv6()) {
							char buffer[100U];
							if (::getnameinfo((struct sockaddr*)&currentTG.IPv6.m_addr, currentTG.IPv6.m_addrLen, buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
								host = "p25:\"" + std::string(buffer) + "\"";
						}
						else if (remoteNetwork.hasIPv4() && currentTG.hasIPv4()) {
							char buffer[100U];
							if (::getnameinfo((struct sockaddr*)&currentTG.IPv4.m_addr, currentTG.IPv4.m_addrLen, buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
								host = "p25:\"" + std::string(buffer) + "\"";
						}
					}

					remoteSocket->write((unsigned char*)host.c_str(), (unsigned int)host.length(), addr, addrLen);
				} else {
					CUtils::dump("Invalid remote command received", buffer, res);
				}
			}
		}

		unsigned int ms = stopWatch.elapsed();
		stopWatch.start();

		reflectors.clock(ms);

		localNetwork->clock(ms);

		if (m_voice != nullptr)
			m_voice->clock(ms);

		hangTimer.clock(ms);
		if (hangTimer.isRunning() && hangTimer.hasExpired()) {
			if (currentTG.isUsed()) {
				LogMessage("Unlinking from %u due to inactivity", currentTG.m_id);

				if (!currentIsStatic) {
					remoteNetwork.writeUnlink(currentTG);
					remoteNetwork.writeUnlink(currentTG);
					remoteNetwork.writeUnlink(currentTG);
				}

				if (m_voice != nullptr)
					m_voice->unlinked();

				currentTG.reset();

				hangTimer.stop();
			}

			currentTG.reset();
		}

		pollTimer.clock(ms);
		if (pollTimer.isRunning() && pollTimer.hasExpired()) {
			// Poll the static TGs
			for (const auto& it : staticTGs)
				remoteNetwork.writePoll(it);

			// Poll the dynamic TG
			if (!currentIsStatic && currentTG.isUsed())
				remoteNetwork.writePoll(currentTG);

			pollTimer.start();
		}

		if (m_writer != nullptr)
			m_writer->clock(ms);

		if (ms < 5U)
			CThread::sleep(5U);
	}

	delete m_voice;

	localNetwork->close();
	delete localNetwork;

	if (remoteSocket != nullptr) {
		remoteSocket->close();
		delete remoteSocket;
	}

	remoteNetwork.close();

	lookup->stop();

	if (m_gps != nullptr) {
		m_writer->close();
		delete m_writer;
		delete m_gps;
	}

	return 0;
}

void CNXDNGateway::createGPS()
{
	if (!m_conf.getAPRSEnabled())
		return;

	std::string callsign  = m_conf.getCallsign();
	std::string rptSuffix = m_conf.getSuffix();
	std::string address   = m_conf.getAPRSAddress();
	unsigned short port   = m_conf.getAPRSPort();
	std::string suffix    = m_conf.getAPRSSuffix();
	bool debug            = m_conf.getDebug();

	m_writer = new CAPRSWriter(callsign, rptSuffix, address, port, debug);

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
		m_writer = nullptr;
		return;
	}

	m_gps = new CGPSHandler(callsign, suffix, m_writer);
}

bool CNXDNGateway::isVoiceBusy() const
{
	if (m_voice == nullptr)
		return false;

	return m_voice->isBusy();
}
