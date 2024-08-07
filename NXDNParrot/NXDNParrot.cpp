/*
*   Copyright (C) 2016,2018,2020,2024 by Jonathan Naylor G4KLX
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

#include "NXDNNetwork.h"
#include "NXDNParrot.h"
#include "StopWatch.h"
#include "Version.h"
#include "Parrot.h"
#include "Thread.h"
#include "Timer.h"
#include "GitVersion.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv)
{
	if (argc > 1) {
		for (int currentArg = 1; currentArg < argc; ++currentArg) {
			std::string arg = argv[currentArg];
			if ((arg == "-v") || (arg == "--version")) {
				::fprintf(stdout, "NXDNParrot version %s git #%.7s\n", VERSION, gitversion);
				return 0;
			}
			else if (arg.substr(0, 1) == "-") {
				::fprintf(stderr, "Usage: NXDNParrot [-v|--version] [-d|--debug] <port>\n");
				return 1;
			}
			else {
				unsigned short port = (unsigned short)::atoi(argv[1U]);
				if (port == 0U) {
					::fprintf(stderr, "NXDNParrot: invalid port number - %s\n", argv[1U]);
					return 1;
				}

				CNXDNParrot parrot(port);
				parrot.run();

				return 0;
			}
		}
	}
}

CNXDNParrot::CNXDNParrot(unsigned short port) :
m_port(port)
{
	CUDPSocket::startup();
}

CNXDNParrot::~CNXDNParrot()
{
	CUDPSocket::shutdown();
}

void CNXDNParrot::run()
{
	CParrot parrot(180U);
	CNXDNNetwork network(m_port);

	bool ret = network.open();
	if (!ret)
		return;

	CStopWatch stopWatch;
	stopWatch.start();

	CTimer watchdogTimer(1000U, 0U, 1500U);
	CTimer turnaroundTimer(1000U, 2U);

	CStopWatch playoutTimer;
	unsigned int count = 0U;
	bool playing = false;

	::fprintf(stdout, "Starting NXDNParrot-%s\n", VERSION);

	for (;;) {
		unsigned char buffer[200U];

		unsigned int len = network.read(buffer, 200U);
		if (len > 0U) {
			parrot.write(buffer, len);
			watchdogTimer.start();

			if ((buffer[9U] & 0x08U) == 0x08U) {
				::fprintf(stdout, "Received end of transmission\n");
				turnaroundTimer.start();
				watchdogTimer.stop();
				parrot.end();
			}
		}

		if (turnaroundTimer.isRunning() && turnaroundTimer.hasExpired()) {
			if (!playing) {
				playoutTimer.start();
				playing = true;
				count = 0U;
			}

			// A frame every 80ms
			unsigned int wanted = playoutTimer.elapsed() / 80U;
			while (count < wanted) {
				len = parrot.read(buffer);
				if (len > 0U) {
					network.write(buffer, len);
					count++;
				} else {
					parrot.clear();
					network.end();
					turnaroundTimer.stop();
					playing = false;
					count = wanted;
				}
			}
		}

		unsigned int ms = stopWatch.elapsed();
		stopWatch.start();

		watchdogTimer.clock(ms);
		turnaroundTimer.clock(ms);

		if (watchdogTimer.isRunning() && watchdogTimer.hasExpired()) {
			turnaroundTimer.start();
			watchdogTimer.stop();
			parrot.end();
		}

		if (ms < 5U)
			CThread::sleep(5U);
	}

	network.close();
}
