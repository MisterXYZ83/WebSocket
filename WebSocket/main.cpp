#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

#include "websocket.h"

int  main()
{
	//inizializzo winsock2
	WSADATA wsa;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Errore inizializzazione : %d", WSAGetLastError());
		return 1;
	}


	//WebSocketServer *server = new WebSocketServer();
	//server->WSSStartServer(50000);


	WebSocketClient *client = new WebSocketClient();
	//client->WSCConnect("echo.websocket.org", 80, "");
	client->WSCConnect("127.0.0.1", 50000, "");


	/////////////// MESSAGE LOOP
	MSG msg;
	BOOL bRet;

	while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0)
	{
		if (bRet == -1)
		{
			// Handle Error
		}
		else
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	WSACleanup();

	return 0;
}