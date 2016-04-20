#include "websocket.h"
#include "websocket_utils.h"
#include <stdlib.h>
#include <string.h>


WebSocketClient::WebSocketClient()
{
	//creo finestra soli messaggi
	memset(&mMessageWindowClass, 0, sizeof(WNDCLASSEX));
	mMessageWindowClass.cbSize = sizeof(WNDCLASSEX);
	mMessageWindowClass.lpfnWndProc = WSCWndProc;
	mMessageWindowClass.hInstance = GetModuleHandle(NULL);
	mMessageWindowClass.lpszClassName = WEBSOCKETCLIENT_MSG_WINDOWCLASS;

	InitializeCriticalSection(&mReceiverLock);
	InitializeConditionVariable(&mReceiverCondition);

	WSCCreateTranceiver(&mLocalTranceiver);

	if (RegisterClassEx(&mMessageWindowClass))
	{
		mMessageWindow = CreateWindowEx(0, WEBSOCKETCLIENT_MSG_WINDOWCLASS, WEBSOCKETCLIENT_MSG_WINDOWCLASS, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, (void *)this);
	}


}



WebSocketClient::~WebSocketClient()
{

}


LRESULT CALLBACK WebSocketClient::WSCWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
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

		WebSocketClient *instance = (WebSocketClient *)GetWindowLong(hwnd, GWLP_USERDATA);

		if (instance)
		{
			//processing messaggi
			res = instance->WSCHandleMessage(uMsg, wParam, lParam);
		}

		if (res >= 0)
		{
			return res;
		}
	}

	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT WebSocketClient::WSCHandleMessage(UINT msg, WPARAM wparam, LPARAM lparam)
{
	
	switch (msg)
	{
		case WSC_CONNECTION_START_HANDSHAKE:
		{
			//send handshake
			EnterCriticalSection(&mReceiverLock);

			//il client deve inviare un handshake del tipo:
			//GET /chat HTTP/1.1
			//Host: server.example.com
			//Upgrade : websocket
			//Connection : Upgrade
			//Sec - WebSocket - Key : dGhlIHNhbXBsZSBub25jZQ ==
			//Sec - WebSocket - Version : 13

			//la key viene creata randomicamente e poi codificata base64
			//il campo host e' quello del server, va indicata la porta se diversa da 80
			//upgrade, version sono obbligatori!

			char *handshake_http_format = "GET /%sHTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-Websocket-Key: %s\r\nSec-Websocket-Version: 13\r\n\r\n";
			char *handshake_http = new char[2048 + 1];
			memset(handshake_http, 0, 2048 + 1);

			char *resource_uri = NULL;
			char *host = NULL;
			char *key = NULL;

			//resource uri
			if (mLocalTranceiver->HandshakeInfos->RequestUri)
			{
				int len = strlen(mLocalTranceiver->HandshakeInfos->RequestUri);

				resource_uri = new char[len + 2];
				memset(resource_uri, 0, len + 2);

				memcpy(resource_uri, mLocalTranceiver->HandshakeInfos->RequestUri, len);
				resource_uri[len] = ' ';
			}
			else
			{
				resource_uri = new char[2];
				memset(resource_uri, 0, 2);

				resource_uri[0] = ' ';
			}

			//campo host:porta
			if (mLocalTranceiver->HandshakeInfos->ServerHostName)
			{
				int len = strlen(mLocalTranceiver->HandshakeInfos->ServerHostName);
				
				int port_len = strlen(mLocalTranceiver->HandshakeInfos->ServerPort);

				host = new char[len + port_len + 2];
				memset(host, 0, len + port_len + 2);

				memcpy(host, mLocalTranceiver->HandshakeInfos->ServerHostName, len);
				host[len] = ':';
				memcpy(host + len + 1, mLocalTranceiver->HandshakeInfos->ServerPort, port_len);
			}
			else
			{
				//errore da gestire
				host = new char[2];
				memset(host, 0, 2);

				host[0] = ' ';

			}

			//chiave token
			unsigned char random_key[16];
			
			int seed = time(NULL);
			srand(seed);

			//creo nonce a 16 byte
			for (int k = 0; k < 16; k++) random_key[k] = (unsigned char)(rand() % 256);

			mLocalTranceiver->HandshakeInfos->WebSocketKey = new char[160 + 1];
			memset(mLocalTranceiver->HandshakeInfos->WebSocketKey, 0, 161);

			//encoding base 64
			Base64encode(mLocalTranceiver->HandshakeInfos->WebSocketKey, (const char *)random_key, 16);

			sprintf_s(handshake_http, 2048, handshake_http_format, resource_uri, host, mLocalTranceiver->HandshakeInfos->WebSocketKey);

			//invio su socket
			int pos = 0;
			int total_len = strlen(handshake_http);
			int sent = total_len;

			do
			{
				pos += send(mLocalTranceiver->TranceiverSocket, (char *)handshake_http + pos, total_len - pos, 0);

				sent -= pos;

				if (SOCKET_ERROR == pos || sent <= 0) break;

			} while (1);


			if (handshake_http) delete handshake_http;
			handshake_http = 0;

			if (resource_uri) delete resource_uri;
			if (host) delete host;
			if (key) delete key;

			//libero il ricevitore per avviare la ricezione
			mReceiverPause = false;

			WakeAllConditionVariable(&mReceiverCondition);

			LeaveCriticalSection(&mReceiverLock);

		}
		break;

		case WSC_RECEIVER_RECV_DATA:
		{
			char *recv_data = (char *)lparam;
			int n_bytes = (int)wparam;

			//elaboro la risposta dal server
			if (mLocalTranceiver->ConnectionState == Opening)
			{
				bool valid_handshake = WSCValidateHandshake(recv_data, n_bytes);

				if (!valid_handshake)
				{
					PostMessage(mMessageWindow, WSC_RECEIVER_FAIL_CONNECTION, 0, 0);
				}
				else
				{
					//connessione aperta
					mLocalTranceiver->ConnectionState = Open;
				}
			}
			else if (mLocalTranceiver->ConnectionState == Open)
			{

				//decode frame
				WebSocketFrame *frame = WSCDecodeFrame(recv_data, n_bytes);

				WSCParseMessage(frame);

			}


			//libero la memoria allocata nel thread di ricezione
			if (recv_data) delete recv_data;
			recv_data = 0;
		}
		break;

		case WSC_RECEIVER_SEND_DATA:
		{
			char *send_data = (char *)lparam;
			int n_bytes = (int)wparam;

			//codifico il pacchetto 


			//libero la memoria
			if (send_data) delete send_data;
			send_data = 0;

		}
		break;

		case WSC_RECEIVER_DATA_MESSAGE:
		{
			WebSocketFrame *data_frame = (WebSocketFrame *)lparam;



			if (data_frame) WebSocketFrame::DeleteWebSocketFrame(data_frame);
		}
		break;

		case WSC_RECEIVER_CONTROL_MESSAGE:
		{
			//invio un pong
			WebSocketFrame *control_frame = (WebSocketFrame *)lparam;

			if (control_frame->IsPingFrame())
			{
				LONG64 len = 0;
				if (control_frame->PayloadLength == 125) len = control_frame->PayloadLength;
				else if (control_frame->PayloadLength == 126) len = control_frame->ExtendedPayloadLength;

				WebSocketFrame *pong_frame = CreatePongFrame(control_frame->Payload, len, 1); //pong e' mascherato da CLIENT => SERVER

				bool ret = WSCSendFrame(pong_frame);

				if (!ret)
				{
					//errore...
				}

				if (pong_frame) WebSocketFrame::DeleteWebSocketFrame(pong_frame);
			
			}

			if (control_frame) WebSocketFrame::DeleteWebSocketFrame(control_frame);
		}
		break;

		case WSC_RECEIVER_ERROR:
		{


		}
		break;

		case WSC_RECEIVER_FAIL_CONNECTION:
		{

		}
		break;
	}
	
	return 0;
}

bool WebSocketClient::WSCValidateHandshake(char *recv_data, int n_bytes)
{
	//devo verificare l'handshake
	http_parser_settings parser_settings;
	http_parser parser;

	http_parser_settings_init(&parser_settings);
	http_parser_init(&parser, HTTP_RESPONSE);	//dobbiamo parsare una REQUEST

	parser_settings.on_headers_complete = WebSocketHandshake_HeadersComplete;
	parser_settings.on_header_field = WebSocketHandshake_HeaderField;
	parser_settings.on_header_value = WebSocketHandshake_HeaderValue;
	parser_settings.on_url = WebSocketHandshake_HeaderURL;

	HttpParserUserData *ud = new HttpParserUserData;
	ud->infos = mLocalTranceiver->HandshakeInfos;
	ud->last_field = 0;

	parser.data = (void *)ud;

	http_parser_execute(&parser, &parser_settings, recv_data, n_bytes);

	//terminato il parsing (parsing sincrono su main thread), struttura handshake riempita
	//verifico validita' campi
	delete ud;
	ud = 0;


	// deve ritornare un return code HTTP pari a 101, altrimenti chiudo
	//deve contenere un campo Upgrade: websocket
	//deve contenere un campo Connection: upgrade
	//deve contenere un campo Sec-WebSocket-Accept: <chiave> e la chiave deve corrispondere ad Base64enc(SHA-1(client-key | 258EAFA5-E914-47DA-95CA-C5AB0DC85B11))

	if (parser.status_code != 101) return false;
	if (!mLocalTranceiver->HandshakeInfos->Connection || _strnicmp(mLocalTranceiver->HandshakeInfos->Connection, "UPGRADE", sizeof("UPGRADE"))) return false;
	if (!mLocalTranceiver->HandshakeInfos->Upgrade || _strnicmp(mLocalTranceiver->HandshakeInfos->Upgrade, "WEBSOCKET", sizeof("WEBSOCKET"))) return false;
	if (!mLocalTranceiver->HandshakeInfos->WebSocketAccept) return false;

	//verifico il token 
	char total_token[1024 + 1];
	memset(total_token, 0, 1024 + 1);

	char *fixed_signature = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	int fixed_signature_len = strlen(fixed_signature);
	int key_len = strlen(mLocalTranceiver->HandshakeInfos->WebSocketKey);

	char digest[100];
	memset(digest, 0, 100);

	memcpy(total_token, mLocalTranceiver->HandshakeInfos->WebSocketKey, strlen(mLocalTranceiver->HandshakeInfos->WebSocketKey));
	memcpy(total_token + key_len, fixed_signature, fixed_signature_len);

	//sha1 e poi base64
	SHA1_CTX sha_ctx;
	sha1_init(&sha_ctx);

	int total_token_len = strlen(total_token);

	sha1_update(&sha_ctx, (unsigned char *)total_token, total_token_len);
	sha1_final(&sha_ctx, (unsigned char *)digest);

	//encode in base64
	int encoded_b64_digest_len = Base64encode_len(20);
	char *encoded_b64_digest = (char *)malloc(encoded_b64_digest_len + 1);
	memset(encoded_b64_digest, 0, encoded_b64_digest_len + 1);

	Base64encode(encoded_b64_digest, digest, 20);

	if (strcmp(encoded_b64_digest, mLocalTranceiver->HandshakeInfos->WebSocketAccept) != 0) return false;

	//tutto ok
	return true;
}

DWORD WINAPI WebSocketClient::WSCReceiverThread(void *data)
{
	WebSocketClient *instance = (WebSocketClient *)data;
	WebSocketTranceiver *tranceiver = NULL;

	if (instance == NULL || instance->mLocalTranceiver == NULL) return (DWORD)-1;
	
	tranceiver = instance->mLocalTranceiver;

	//ricezione dati
	char *receiver_buffer = 0;

	int received = 0;
	bool end_rec = false;
	int n_realloc = 1;

	//loop ricezione
	while (1)
	{
		//lock di avvio
		EnterCriticalSection(&instance->mReceiverLock);
		while (instance->mReceiverPause) SleepConditionVariableCS(&instance->mReceiverCondition, &instance->mReceiverLock, INFINITE);
		LeaveCriticalSection(&instance->mReceiverLock);


		//carico dati fino a che ci sono
		//prealloco il buffer, sara' deallocato dal consumatore!
		receiver_buffer = new char[RECV_BUFFER_SIZE + 1];
		memset(receiver_buffer, 0, RECV_BUFFER_SIZE + 1);
		received = 0;

		do
		{
			received += recv(tranceiver->TranceiverSocket, receiver_buffer + received, RECV_BUFFER_SIZE, 0);

			//printf("MESSAGE: ");
			//for (int k = 0; k < received; k++) printf("%02X ", (unsigned char)receiver_buffer[k]);
			//printf("\r\n\r\n");

			if (received == RECV_BUFFER_SIZE)
			{
				//rialloco il buffer
				n_realloc++;

				char *tmp_buffer = new char[RECV_BUFFER_SIZE * n_realloc];
				memset(tmp_buffer, 0, RECV_BUFFER_SIZE * n_realloc);

				//copio tutto
				memcpy(tmp_buffer, receiver_buffer, received);

				delete receiver_buffer;

				//scambio buffer;
				receiver_buffer = tmp_buffer;
			}
			else end_rec = true;

		} while (!end_rec);

		//raggiunto EOS su socket, verifico condizione
		if (received > 0)
		{
			PostMessage(instance->mMessageWindow, WSC_RECEIVER_RECV_DATA, (WPARAM)received, (LPARAM)receiver_buffer);
		}
		else
		{
			//errore, invio, dealloco
			if (receiver_buffer) delete receiver_buffer;

			PostMessage(instance->mMessageWindow, WSC_RECEIVER_ERROR, 0, 0);
			return (DWORD)-1;
		}

	}


	return (DWORD)-1;
}

int WebSocketClient::WSCCreateTranceiver(WebSocketTranceiver **t)
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


int WebSocketClient::WSCDeleteTranceiver(WebSocketTranceiver *t)
{
	if (t)
	{
		//sblocco il thread se necessario
		EnterCriticalSection(&mReceiverLock);

		mReceiverPause = false;

		WakeAllConditionVariable(&mReceiverCondition);

		LeaveCriticalSection(&mReceiverLock);


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

			delete t->HandshakeInfos;
		}
		t->HandshakeInfos = 0;

		delete t;
	}

	return 0;
}

WebSocketFrame *WebSocketClient::WSCDecodeFrame(char *data, int size)
{
	//decodifica del header websocket
	WebSocketFrame *frame = NULL;

	if ( data == NULL || size <= 0) return frame;

	int next_byte = 0;

	//analizzo i dati ricevuti
	BYTE fin = (data[next_byte] & 0x80) >> 7;
	BYTE res1 = (data[next_byte] & 0x40) >> 6;
	BYTE res2 = (data[next_byte] & 0x20) >> 5;
	BYTE res3 = (data[next_byte] & 0x10) >> 4;
	BYTE opcode = (data[next_byte] & 0x0F) >> 0;

	++next_byte;

	BYTE masked = (data[next_byte] & 0x80) >> 7;
	BYTE payload_len = (data[next_byte] & 0x7F) >> 0;

	unsigned long total_payload_len = 0;

	//verifico se ho un payload extra
	if (payload_len < 125)
	{
		total_payload_len = payload_len;
		++next_byte;
	}
	else if (payload_len == 126)
	{
		//leggo altri 2 byte dal frame
		total_payload_len = (data[++next_byte] << 0) + (data[++next_byte + 2] << 8);
	}
	else if (payload_len == 127)
	{
		//leggo altri 
		total_payload_len = (data[++next_byte] << 0) + (data[++next_byte] << 8) + (data[++next_byte] << 16);
		total_payload_len += (data[++next_byte] << 24) + (data[++next_byte] << 32) + (data[++next_byte] << 40);
		total_payload_len += (data[++next_byte] << 48) + (data[++next_byte] << 56);
	}

	BYTE mask0 = 0;
	BYTE mask1 = 0;
	BYTE mask2 = 0;
	BYTE mask3 = 0;

	if (masked)
	{
		mask0 = data[next_byte++];
		mask1 = data[next_byte++];
		mask2 = data[next_byte++];
		mask3 = data[next_byte++];
	}

	//ok, creo un frame
	frame = new WebSocketFrame;
	memset(frame, 0, sizeof(WebSocketFrame));

	frame->OwnerTranceiver = this->mLocalTranceiver;

	frame->Final = fin;
	frame->Reserved1 = res1;
	frame->Reserved2 = res2;
	frame->Reserved3 = res3;
	frame->OpCode = opcode;
	frame->PayloadLength = payload_len;
	frame->ExtendedPayloadLength = total_payload_len;
	frame->Mask[0] = mask0;
	frame->Mask[1] = mask1;
	frame->Mask[2] = mask2;
	frame->Mask[3] = mask3;
	frame->IsMasked = masked;
	frame->Payload = 0;
	frame->FragmentIndex = 0;

	//copio il payload e decodifico
	frame->Payload = new unsigned char[total_payload_len + 1];
	memset(frame->Payload, 0, total_payload_len + 1);

	memcpy(frame->Payload, &data[next_byte], total_payload_len);

	if (frame->IsMasked) WebSocketPayloadTransform(frame->Payload, frame->Mask, total_payload_len);

	return frame;
}

bool WebSocketClient::WSCParseMessage(WebSocketFrame *actual_frame)
{
	WebSocketTranceiver *tc = mLocalTranceiver;

	if (!actual_frame || !tc) return false;

	//frame frammentato
	//1: FIN = 0 && OPCODE != 0 && OPCODE not Control
	//N: FIN = 0 && OPCODE == 0 
	//3: FIN = 1 && OPCODE == 0

	//frame singolo
	// FIN = 1

	//1 (frammento iniziale)
	if (!tc->FragmentedTransferActive && actual_frame->Final == 0 && actual_frame->IsNonControlFrame())
	{
		//e' il frame iniziale di un messaggio frammentato
		tc->FragmentedTransferActive = true;

		WebSocketFrameElement *elem = new WebSocketFrameElement;

		elem->Frame = actual_frame;
		elem->Frame->FragmentIndex = ++WebSocketFrameElement::FragmentCounter;

		if (!tc->FramedMessage)
		{
			//primo elemento
			elem->NextFrame = elem;
			elem->PreviousFrame = elem;

			tc->FramedMessage = elem;
		}
		else
		{
			WebSocketFrameElement *head = tc->FramedMessage;

			elem->Frame = actual_frame;
			elem->Frame->FragmentIndex = WebSocketFrameElement::FragmentCounter;

			elem->NextFrame = NULL;
			elem->PreviousFrame = head->PreviousFrame;

			head->PreviousFrame->NextFrame = elem;

			tc->FragmentedTransferActive = !actual_frame->Final;
		}

		PostMessage(mMessageWindow, WSC_RECEIVER_OPEN_FRAGMENT, 0, 0);

		return true;
	}

	//N: (frammenti intermedi) // 3: finale
	if (tc->FragmentedTransferActive && actual_frame->IsContinuationFrame() && tc->FramedMessage)
	{
		WebSocketFrameElement *elem = new WebSocketFrameElement;

		WebSocketFrameElement *head = tc->FramedMessage;

		elem->Frame = actual_frame;
		elem->Frame->FragmentIndex = WebSocketFrameElement::FragmentCounter;

		elem->NextFrame = NULL;
		elem->PreviousFrame = head->PreviousFrame;

		head->PreviousFrame->NextFrame = elem;

		tc->FragmentedTransferActive = !actual_frame->Final;

		if (actual_frame->Final) PostAppMessage(mMessageWindow, WSC_RECEIVER_CLOSE_FRAGMENT, 0, 0);

		return true;
	}

	//frame singolo (non frammentato)
	if (!tc->FragmentedTransferActive && actual_frame->Final && !actual_frame->IsContinuationFrame())
	{
		//check se e' di controllo
		if (actual_frame->IsControlFrame())
		{
			PostMessage(mMessageWindow, WSC_RECEIVER_CONTROL_MESSAGE, 0, (LPARAM)actual_frame);
		}
		else if (actual_frame->IsNonControlFrame())
		{
			PostMessage(mMessageWindow, WSC_RECEIVER_DATA_MESSAGE, 0, (LPARAM)actual_frame);
		}
	}

	return false;
}


bool WebSocketClient::WSCSendFrame(WebSocketFrame *frame)
{
	//creo il pacchetto
	unsigned char *data_to_send = NULL;
	LONG64 total_len = 2;

	//la dim del pacchetto totale e' data da 2 + (2/8 in base al payload len) + (0/4 in base a masked) + payload_len

	if (frame->PayloadLength <= 125) total_len += frame->PayloadLength;
	else if (frame->PayloadLength == 126) total_len += 2 + frame->ExtendedPayloadLength;
	else total_len += 8 + frame->ExtendedPayloadLength;

	if (frame->IsMasked) total_len += 4;

	//creo il pacchetto
	data_to_send = new unsigned char[total_len];
	memset(data_to_send, 0, total_len);

	data_to_send[0] |= frame->Final << 7;
	data_to_send[0] |= frame->Reserved1 << 6;
	data_to_send[0] |= frame->Reserved2 << 5;
	data_to_send[0] |= frame->Reserved3 << 4;
	data_to_send[0] |= frame->OpCode;

	data_to_send[1] |= frame->IsMasked << 7;
	data_to_send[1] |= frame->PayloadLength;

	int next_byte = 2;

	if (frame->PayloadLength == 126)
	{
		//2 byte extra
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0x00FF;
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0xFF00 >> 8;
	}
	else if (frame->PayloadLength == 127)
	{
		//8 byte extra
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0x00000000000000FF;
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0x000000000000FF00 >> 8;
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0x0000000000FF0000 >> 16;
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0x00000000FF000000 >> 24;
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0x000000FF00000000 >> 32;
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0x0000FF0000000000 >> 40;
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0x00FF000000000000 >> 48;
		data_to_send[next_byte++] = frame->ExtendedPayloadLength & 0xFF00000000000000 >> 56;
	}

	if (frame->IsMasked)
	{
		data_to_send[next_byte++] = frame->Mask[0];
		data_to_send[next_byte++] = frame->Mask[1];
		data_to_send[next_byte++] = frame->Mask[2];
		data_to_send[next_byte++] = frame->Mask[3];
	}

	//copio il payload
	if (total_len - next_byte)
	{
		LONG64 data_len = total_len - next_byte;

		memcpy(data_to_send + next_byte, frame->Payload, data_len);
	}

	//send
	int pos = 0;
	int sent = total_len;

	do
	{
		pos += send(mLocalTranceiver->TranceiverSocket, (char *)data_to_send + pos, total_len - pos, 0);

		sent -= pos;

		if (SOCKET_ERROR == pos || sent <= 0) break;

	} while (1);

	if (SOCKET_ERROR == pos || sent < 0)
	{
		//errore di invio sulla socket, abort
		if (data_to_send) delete data_to_send;
		data_to_send = 0;

		return false;
	}
	
	return true;
}


int WebSocketClient::WSCConnect(char *address, int port, char *server_res)
{
	if (mLocalTranceiver == NULL) return -1;
	if (mLocalTranceiver->TranceiverSocket != INVALID_SOCKET) return -1; //gia connesso!

	struct addrinfo *result = NULL, *ptr = NULL, hints;
	
	int iResult;

	/////////////////DEBUG
	memset(mLocalTranceiver->LocalAddress, 0, sizeof("127.0.0.1") + 1);
	memcpy(mLocalTranceiver->LocalAddress, "127.0.0.1", sizeof("127.0.0.1"));
	///////////////////

	char port_buffer[10];
	memset(port_buffer, 0, 10);

	SOCKET client_socket = INVALID_SOCKET;

	_itoa_s(port, port_buffer, 10);

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	//risolvo con dns
	iResult = getaddrinfo(address, port_buffer, &hints, &result);
	
	if (iResult != 0) 
	{
		printf("getaddrinfo failed with error: %d\n", iResult);
		return -1;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{

		client_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		
		if (client_socket == INVALID_SOCKET)
		{
			printf("socket failed with error: %ld\n", WSAGetLastError());
			//WSACleanup();
			return -1;
		}

		// Connect to server.
		iResult = connect(client_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
	
		if (iResult == SOCKET_ERROR)
		{
			closesocket(client_socket);
			client_socket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (client_socket == INVALID_SOCKET)
	{
		printf("Unable to connect to server!\n");
		//WSACleanup();
		return 1;
	}

	mLocalTranceiver->TranceiverSocket = client_socket;
	mLocalTranceiver->ConnectionState = Opening;

	if ( server_res != NULL ) mLocalTranceiver->HandshakeInfos->RequestUri = _strdup(server_res);
	else mLocalTranceiver->HandshakeInfos->RequestUri = NULL;

	mLocalTranceiver->HandshakeInfos->ServerHostName = _strdup(address);

	mLocalTranceiver->HandshakeInfos->ServerPort = _strdup(port_buffer);

	//imposto in wait il thread
	mReceiverPause = true;

	//creo thread di ricezione
	mLocalTranceiver->TranceiverThread = CreateThread(NULL, 0, WSCReceiverThread, (void *)this, 0, &mLocalTranceiver->TranceiverThreadID);

	//invio
	PostMessage(mMessageWindow, WSC_CONNECTION_START_HANDSHAKE, 0, 0);
	
	return 0;
}

int WebSocketClient::WSCSendData(char *payload, int size)
{
	//copio i dati da inviare su un buffer che sara liberato dalla routine di send

	if (payload && size > 0)
	{
		char *to_send = new char[size];
		memset(to_send, 0, size);

		memcpy(to_send, payload, size);

		PostMessage(mMessageWindow, WSC_RECEIVER_SEND_DATA, (WPARAM)size, (LPARAM)to_send);
	}

	return size > 0;
}