#include "websocket.h"
#include "websocket_utils.h"
#include <stdlib.h>
#include <string.h>


LRESULT CALLBACK WebSocketServer::WSSWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	//create
	LONG_PTR res = 0;

	if (WM_CREATE == uMsg)
	{
		CREATESTRUCT *params = (CREATESTRUCT *)lParam;
		SetWindowLong(hwnd, GWLP_USERDATA, (LONG)params->lpCreateParams);
	}
	else
	{
		res = -1;

		WebSocketServer *instance = (WebSocketServer *)GetWindowLong(hwnd, GWLP_USERDATA);

		if (instance)
		{
			//processing messaggi
			res = instance->WSSHandleMessage(uMsg, wParam, lParam);
		}

		if (res >= 0)
		{
			return res;
		}
	}

	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT WebSocketServer::WSSHandleMessage(UINT msg, WPARAM wparam, LPARAM lparam)
{
	///processa i messaggi
	switch (msg)
	{
		case WSS_CONNECTION_INCOMING:
		{
			SOCKET clientSocket = (SOCKET)lparam;

			//ricevuta una richiesta di connessione
			if (!mTranceiver)
			{
				//creo un thread per il tranceiver
				WSSCreateTranceiver(&mTranceiver);

				mTranceiver->ConnectionState = Opening;
				mTranceiver->TranceiverSocket = clientSocket;
				mTranceiver->WSServer = this;
				mTranceiver->TranceiverThread = CreateThread(NULL, 0, WSSTranceiverThread, (void *)mTranceiver, 0, &mTranceiver->TranceiverThreadID);
			}
			else
			{
				//gia attivo un client, chiudo
				closesocket(clientSocket);
				clientSocket = NULL;
			}

		}
		break;

		case WSS_RECEIVER_NEW_DATA:
		{
			char *recv_data = (char *)lparam;
			int n_bytes = (int)wparam;
			
			//consumo i dati
			if (mTranceiver->ConnectionState == Opening)
			{
				//opening, devo parsare l'intestazione HTTP
				
				int ret = WSSParseHandshake(mTranceiver, recv_data, n_bytes);

				if (!ret)
				{
					//valido, invio risposta
					//calcolo il websocket token

					// A Status - Line with a 101 response code as per RFC 2616[RFC2616]. Such a response could look like "HTTP/1.1 101 Switching Protocols".
					//	An |Upgrade| header field with value "websocket" as per RFC 2616[RFC2616].
					//	A  |Connection| header field with value "Upgrade".
					//	A  |Sec-WebSocket-Accept| header field. The value of this header field is constructed by concatenating / key / , 
					// defined above in step 4 in Section 4.2.2, with the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", taking the SHA - 1 hash 
					// of this concatenated value to obtain a 20 - byte value and base64 - encoding(see Section 4 of[RFC4648]) this 20 - byte hash.
					
					//calcolo il token di risposta cosi: BASE64_ENC(SHA-1(KEY + 258EAFA5-E914-47DA-95CA-C5AB0DC85B11))
					SHA1_CTX sha_ctx;
					sha1_init(&sha_ctx);

					char *fixed_signature = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
					char digest[20];
					memset(digest, 0, 20);

					int fixed_signature_len = strlen(fixed_signature);
					int ws_token_len = strlen(mTranceiver->HandshakeInfos->WebSocketKey);
					
					int full_string_len = fixed_signature_len + ws_token_len;
					
					char *full_string = (char *)malloc(full_string_len+1);
					
					memset(full_string, 0, full_string_len+1);

					memcpy(full_string, mTranceiver->HandshakeInfos->WebSocketKey, ws_token_len);
					memcpy(full_string + ws_token_len, fixed_signature, fixed_signature_len);

					sha1_update(&sha_ctx, (unsigned char *)full_string, full_string_len);
					sha1_final(&sha_ctx, (unsigned char *)digest);

					//encode in base64
					int encoded_b64_digest_len = Base64encode_len(20);
					char *encoded_b64_digest = (char *)malloc(encoded_b64_digest_len+1);
					memset(encoded_b64_digest, 0, encoded_b64_digest_len+1);

					Base64encode(encoded_b64_digest, digest, 20);

					//invio pacchetto di risposta
					char handshake_answ[10001];
					memset(handshake_answ, 0, 10001);

					_snprintf_s(handshake_answ, 10000, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-Websocket-Accept: %s\r\n\r\n", encoded_b64_digest);

					int pos = 0;
					int to_send = strnlen_s(handshake_answ, 1000);
					
					do
					{
						pos += send(mTranceiver->TranceiverSocket, handshake_answ + pos, to_send - pos, 0);
						
						to_send -= pos;

						if (SOCKET_ERROR == pos || to_send <= 0 ) break;

					} while (1);

					if (SOCKET_ERROR == pos || to_send < 0 )
					{
						//errore di invio sulla socket, abort
						WSSDeleteTranceiver(mTranceiver);
					}
					else
					{
						//tutto ok! cambio stato
						mTranceiver->ConnectionState = Open;
					}

				}
				else
				{
					//errore nell'handshake, chiudo la connessione
					//gia attivo un client, chiudo
					WSSDeleteTranceiver(mTranceiver);
				}
			}
			else if (mTranceiver->ConnectionState == Open)
			{
				//connessione aperta, parsing dei frame Websocket
				
				WebSocketFrame *actual_frame = WSSDecodeFrame(mTranceiver, recv_data, n_bytes);

				bool ret = WSSParseMessage(mTranceiver, actual_frame);

			}
			else if (mTranceiver->ConnectionState == Closing)
			{
				//in chiusura

				//chiudo la socket del ricevitore
				WSSDeleteTranceiver(mTranceiver);
			}
			else
			{
				//chiusa
				WSSDeleteTranceiver(mTranceiver);
			}
			

			//libero la memoria
			if (recv_data ) delete recv_data;
			recv_data = 0;

		}
		break;

		case WSS_RECEIVED_CONTROL_MESSAGE:
		{

			//invio un pong
			WebSocketFrame *control_frame = (WebSocketFrame *)lparam;
			
			if (control_frame->IsPingFrame())
			{
				LONG64 len = 0;
				if (control_frame->PayloadLength == 125) len = control_frame->PayloadLength;
				else if (control_frame->PayloadLength == 126) len = control_frame->ExtendedPayloadLength;

				WebSocketFrame *pong_frame = CreatePongFrame(control_frame->Payload, len, 0); //pong non e' mascherato da SERVER => CLIENT

				bool ret = WSSSendFrame(mTranceiver, pong_frame);

				if (!ret)
				{
					//errore...
				}

				if (pong_frame) WebSocketFrame::DeleteWebSocketFrame(pong_frame);
				if (control_frame) WebSocketFrame::DeleteWebSocketFrame(control_frame);
			}

		}
		break;

		case WSS_RECEIVED_DATA_MESSAGE:
		{
			//invio un pong
			WebSocketFrame *data_message = (WebSocketFrame *)lparam;

			//fai qualcosa con il pacchetto


			//libero memoria
			if (data_message) WebSocketFrame::DeleteWebSocketFrame(data_message);

		}
		break;

		case WSS_RECEIVER_ERROR:
		{

		}
		break;

		case WSS_RECEIVED_CLOSE_FRAGMENT:
		{

		}
		break;

		case WSS_RECEIVED_OPEN_FRAGMENT:
		{

		}
		break;

	}

	return 0;
}

//solo un bypass per la funzione statica
DWORD WINAPI WebSocketServer::WSSListenThread(void *data)
{
	WebSocketServer *instance = (WebSocketServer *)data;

	if (instance)
	{
		instance->WSSThreadRoutine();
	}

	return (DWORD)-1;
}

void WebSocketServer::WSSThreadRoutine()
{
	while (mThreadActive)
	{
		EnterCriticalSection(&mListenerLock);
		
		while ( !mListeningActive )
		{
			//listener non attivo, sleep per 1 secondo poi verifico
			SleepConditionVariableCS(&mListenerCondition, &mListenerLock, 1000);
		}

		//ora per interrompere il listening devo
		//chiudere  la socket (in alternativa configurare come non blocking la socket)
		
		//listening attivo!
		//definisco un task di ricezione e socket relativa
		SOCKET clientSocket = INVALID_SOCKET;

		// Accept a client socket
		clientSocket = accept(mListenSocket, NULL, NULL);

		if (clientSocket == INVALID_SOCKET) 
		{
			printf("Errore accept: %d\n", WSAGetLastError());
		}
		else
		{
			//creo il task di ricezione/invio su un altro thread
			//notificando al main thread
			PostMessage(mMessageWindow, WSS_CONNECTION_INCOMING, 0, (LPARAM)clientSocket);
		}
		
		LeaveCriticalSection(&mListenerLock);
	}
}

WebSocketServer::WebSocketServer()
{
	InitializeCriticalSection(&mListenerLock);
	InitializeConditionVariable(&mListenerCondition);

	//creo finestra soli messaggi
	memset(&mMessageWindowClass, 0, sizeof(WNDCLASSEX));
	mMessageWindowClass.cbSize = sizeof(WNDCLASSEX);
	mMessageWindowClass.lpfnWndProc = WSSWndProc;
	mMessageWindowClass.hInstance = GetModuleHandle(NULL);
	mMessageWindowClass.lpszClassName = WEBSOCKETSERVER_MSG_WINDOWCLASS;

	if (RegisterClassEx(&mMessageWindowClass))
	{
		mMessageWindow = CreateWindowEx(0, WEBSOCKETSERVER_MSG_WINDOWCLASS, WEBSOCKETSERVER_MSG_WINDOWCLASS, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, (void *)this);
	}
	
	mThreadActive = 1;
	mListeningActive = 0;
	mListenerThread = CreateThread(NULL, 0, WSSListenThread, (void *)this, 0, &mListenerThreadID);

}


int WebSocketServer::WSSStartServer(int listen_port)
{
	struct addrinfo *result = NULL, *ptr = NULL, hints;

	char port_buffer[1001];
	memset(port_buffer, 0, 1001);

	_itoa_s(listen_port, port_buffer, 10);

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;


	int res = getaddrinfo(NULL, port_buffer, &hints, &result);
	if (res != 0) 
	{
		printf("getaddrinfo failed: %d\n", res);
		//WSACleanup();
		return 1;
	}

	mListenSocket = INVALID_SOCKET;
	
	//creo la socket
	mListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	if (mListenSocket == INVALID_SOCKET) 
	{
		printf("Errore nell'apertura della socket: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		//WSACleanup();
		return 1;
	}

	//bindo la socket
	res = bind(mListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (res == SOCKET_ERROR) 
	{
		printf("Bind fallito: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(mListenSocket);;
		return 1;
	}

	//libero la memoria per l'indirizzo
	freeaddrinfo(result);

	//attivo il listener
	mListeningActive = 1;

	if (listen(mListenSocket, 1) == SOCKET_ERROR)
	{
		printf("Errore in avvio listening: %ld\n", WSAGetLastError());
		closesocket(mListenSocket);
		
		EnterCriticalSection(&mListenerLock);

		mListeningActive = 0;
		
		LeaveCriticalSection(&mListenerLock);

		WakeAllConditionVariable(&mListenerCondition);

		return 1;
	}



	return 0;

}


int WebSocketServer::WSSCreateTranceiver(WebSocketTranceiver **t)
{
	int ret = -1;

	if (t)
	{
		*t = new WebSocketTranceiver;
		memset(*t, 0, sizeof(WebSocketTranceiver));

		(*t)->TranceiverSocket = INVALID_SOCKET;
		(*t)->TranceiverThread = 0;
		(*t)->TranceiverThreadID = 0;

		(*t)->HandshakeInfos = new WebSocketHandshakeInfo;
		memset((*t)->HandshakeInfos, 0, sizeof(WebSocketHandshakeInfo));
		(*t)->HandshakeInfos->Tranceiver = *t;
		ret = 0;
	}

	return ret;
}


int WebSocketServer::WSSDeleteTranceiver(WebSocketTranceiver *t)
{
	if (t)
	{
		//chiudo la socket del task
		closesocket(t->TranceiverSocket);

		//attendo la chiusura del task
		WaitForSingleObject(&t->TranceiverThread, INFINITE);

		if (t->HandshakeInfos)
		{
			if (t->HandshakeInfos->Connection) delete t->HandshakeInfos->Connection;
			if (t->HandshakeInfos->Host) delete t->HandshakeInfos->Host;
			if (t->HandshakeInfos->Method) delete t->HandshakeInfos->Method;
			if (t->HandshakeInfos->RequestUri) delete t->HandshakeInfos->RequestUri;
			if (t->HandshakeInfos->ServerPort) delete t->HandshakeInfos->ServerPort;
			if (t->HandshakeInfos->Upgrade) delete t->HandshakeInfos->Upgrade;
			if (t->HandshakeInfos->ServerHostName) delete t->HandshakeInfos->ServerHostName;
			if (t->HandshakeInfos->WebSocketKey) delete t->HandshakeInfos->WebSocketKey;
			if (t->HandshakeInfos->WebSocketVersion) delete t->HandshakeInfos->WebSocketVersion;
			if (t->HandshakeInfos->WebSocketAccept) delete t->HandshakeInfos->WebSocketAccept;
			delete t->HandshakeInfos;
		}
		t->HandshakeInfos = 0;

		delete t;
		t = 0;
	}

	return 0;
}

int WebSocketServer::WSSStopServer()
{
	//basta chiudere la socket di ascolto
	closesocket(mListenSocket);

	mListenSocket = INVALID_SOCKET;

	mListeningActive = 0;

	return 0;
}


WebSocketServer::~WebSocketServer()
{
	//chiudo finestra, thread e deregistro la classe
	mThreadActive = 0;
	mListeningActive = 0;

	//join del thread;
	WaitForSingleObject(mListenerThread, INFINITE);

	//thread morto, chiudo socket

	//chiudo finestra e classe
	DestroyWindow(mMessageWindow);

	UnregisterClass(WEBSOCKETSERVER_MSG_WINDOWCLASS, NULL);

	DeleteCriticalSection(&mListenerLock);
}