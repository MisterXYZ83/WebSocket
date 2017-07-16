#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#include "http_parser.h"

#pragma comment(lib, "Ws2_32.lib")




#define WEBSOCKETSERVER_MSG_WINDOWCLASS TEXT("WEBSOCKETSERVER_MSG_WINDOW")
#define WEBSOCKETCLIENT_MSG_WINDOWCLASS TEXT("WEBSOCKETCLIENT_MSG_WINDOW")

#define WEBSOCKETSERVER_MESSAGE_BASE		WM_APP + 1
#define WSS_CONNECTION_INCOMING				WEBSOCKETSERVER_MESSAGE_BASE + 0
#define WSS_RECEIVER_ERROR					WEBSOCKETSERVER_MESSAGE_BASE + 1
#define WSS_RECEIVER_NEW_DATA				WEBSOCKETSERVER_MESSAGE_BASE + 2
#define WSS_RECEIVED_PING					WEBSOCKETSERVER_MESSAGE_BASE + 3
#define WSS_RECEIVED_TEXT					WEBSOCKETSERVER_MESSAGE_BASE + 4
#define WSS_RECEIVED_BINARY					WEBSOCKETSERVER_MESSAGE_BASE + 5
#define WSS_RECEIVED_OPEN_FRAGMENT			WEBSOCKETSERVER_MESSAGE_BASE + 6
#define WSS_RECEIVED_CLOSE_FRAGMENT			WEBSOCKETSERVER_MESSAGE_BASE + 7
#define WSS_RECEIVED_DATA_MESSAGE			WEBSOCKETSERVER_MESSAGE_BASE + 8
#define WSS_RECEIVED_CONTROL_MESSAGE		WEBSOCKETSERVER_MESSAGE_BASE + 9



#define WEBSOCKETCLIENT_MESSAGE_BASE		WM_APP + 1
#define WSC_CONNECTION_START_HANDSHAKE		WEBSOCKETCLIENT_MESSAGE_BASE + 1
#define WSC_RECEIVER_ERROR					WEBSOCKETCLIENT_MESSAGE_BASE + 2
#define WSC_RECEIVER_RECV_DATA				WEBSOCKETCLIENT_MESSAGE_BASE + 3
#define WSC_RECEIVER_SEND_DATA				WEBSOCKETCLIENT_MESSAGE_BASE + 4
#define WSC_RECEIVER_CONTROL_MESSAGE		WEBSOCKETCLIENT_MESSAGE_BASE + 5
#define WSC_RECEIVER_DATA_MESSAGE			WEBSOCKETCLIENT_MESSAGE_BASE + 6
#define WSC_RECEIVER_FAIL_CONNECTION		WEBSOCKETCLIENT_MESSAGE_BASE + 7
#define WSC_RECEIVER_OPEN_FRAGMENT			WEBSOCKETCLIENT_MESSAGE_BASE + 8
#define WSC_RECEIVER_CLOSE_FRAGMENT			WEBSOCKETCLIENT_MESSAGE_BASE + 9
#define WSC_RECEIVER_NEXT_FRAGMENT			WEBSOCKETCLIENT_MESSAGE_BASE + 10
#define WSC_RECEIVER_PUSH_DATA				WEBSOCKETCLIENT_MESSAGE_BASE + 11

#define RECV_BUFFER_SIZE		128

enum WebSocketConnectionState { Opening = 0, Open, Closing, Closed };

class WebSocketServer;
class WebSocketTranceiver;

#define WEBSOCKET_OPCODE_CONTINUATION	0x00

#define WEBSOCKET_OPCODE_TEXT	0x01
#define WEBSOCKET_OPCODE_BINARY	0x02

#define WEBSOCKET_OPCODE_CLOSE	0x08
#define WEBSOCKET_OPCODE_PING	0x09
#define WEBSOCKET_OPCODE_PONG	0x0A

struct WebSocketFrame
{
	unsigned long FragmentIndex;

	bool Final;

	char Reserved1;
	char Reserved2;
	char Reserved3;

	unsigned char OpCode;

	bool IsMasked;

	unsigned char PayloadLength;

	LONG64 ExtendedPayloadLength;

	unsigned char Mask[4] = { 0, 0, 0, 0 };

	unsigned char *Payload;	//copia locale

	WebSocketTranceiver *OwnerTranceiver;

	bool IsControlFrame() { return OpCode >= WEBSOCKET_OPCODE_CLOSE; }
	bool IsContinuationFrame() { return OpCode == WEBSOCKET_OPCODE_CONTINUATION; }
	bool IsNonControlFrame() { return OpCode > WEBSOCKET_OPCODE_CONTINUATION && OpCode < WEBSOCKET_OPCODE_CLOSE; }
	bool IsPingFrame() { return OpCode == WEBSOCKET_OPCODE_PING; }

	static void DeleteWebSocketFrame(WebSocketFrame *frame)
	{
		if (frame)
		{
			if (frame->Payload) delete frame->Payload;

			frame->Payload = NULL;

			delete frame;
			frame = NULL;
		}
	}
};

struct WebSocketFrameElement
{
	static unsigned long FragmentCounter;

	WebSocketFrame *Frame;

	WebSocketFrameElement *PreviousFrame;
	WebSocketFrameElement *NextFrame;
};

struct WebSocketHandshakeInfo
{
	char *WebSocketKey;
	char *WebSocketAccept;
	char *WebSocketVersion;
	char *RequestUri;
	char *ServerHostName;
	char *ServerPort;
	char *Method;
	char *Host;
	char *Upgrade;
	char *Connection;

	http_parser *HttpParser;
	WebSocketTranceiver *Tranceiver;
};

struct WebSocketTranceiver
{
	HANDLE TranceiverThread;
	DWORD TranceiverThreadID;
	SOCKET TranceiverSocket;
	char LocalAddress[201];

	char *DataBuffer;
	int DataBuffer_Size;

	WebSocketServer *WSServer;

	WebSocketConnectionState ConnectionState;

	//parametri della connessione
	WebSocketHandshakeInfo *HandshakeInfos;

	//lista pacchetti per framing
	WebSocketFrameElement *FramedMessage;
	bool FragmentedTransferActive;

	bool mReceiverPause;
};

class WebSocketServer
{
		
private:

	static LRESULT CALLBACK WSSWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static DWORD WINAPI WSSListenThread(void *data);
	static DWORD WINAPI WSSTranceiverThread(void *data);

	LRESULT WSSHandleMessage(UINT msg, WPARAM wparam, LPARAM lparam);
	void WSSThreadRoutine();

	WNDCLASSEX	mMessageWindowClass;
	HWND	mMessageWindow;

	HANDLE	mListenerThread;
	DWORD	mListenerThreadID;

	bool mThreadActive;
	bool mListeningActive;

	CRITICAL_SECTION	mListenerLock;
	CONDITION_VARIABLE	mListenerCondition;

	SOCKET mListenSocket;

	WebSocketTranceiver *mTranceiver;

	int WSSCreateTranceiver(WebSocketTranceiver **t);
	int WSSDeleteTranceiver(WebSocketTranceiver *t);
 
	int WSSParseHandshake(WebSocketTranceiver *tc, char *data, int size);

	WebSocketFrame *WSSDecodeFrame(WebSocketTranceiver *tc, char *data, int size);
	bool WSSParseMessage(WebSocketTranceiver *tc, WebSocketFrame *actual_frame);
	bool WSSSendFrame(WebSocketTranceiver *tc, WebSocketFrame *frame);

public:

	WebSocketServer();
	~WebSocketServer();

	int WSSStartServer(int listen_port);
	int WSSStopServer();

};

class WebSocketClient
{

private:

	WebSocketTranceiver *mLocalTranceiver;

	static LRESULT CALLBACK WSCWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
	static DWORD WINAPI WSCReceiverThread(void *data);

	LRESULT WSCHandleMessage(UINT msg, WPARAM wparam, LPARAM lparam);

	WNDCLASSEX	mMessageWindowClass;
	HWND	mMessageWindow;

	int WSCCreateTranceiver(WebSocketTranceiver **t);
	int WSCDeleteTranceiver(WebSocketTranceiver *t);

	WebSocketFrame *WSCDecodeFrame(char *data, int size);
	WebSocketFrame *WSCDecodeFrame(char *data, int size, int *offset, int *status);
	bool WSCParseMessage(WebSocketFrame *actual_frame, int residual = 0);
	bool WSCSendFrame(WebSocketFrame *frame);
	bool WSCValidateHandshake(char *data, int len, int *header_len = 0);

	CRITICAL_SECTION	mReceiverLock;
	CONDITION_VARIABLE	mReceiverCondition;

	bool mReceiverPause;

public:

	WebSocketClient();
	~WebSocketClient();

	int WSCConnect(char *address, int port, char *server_res);
	int WSCSendData(char *payload, int size);

};