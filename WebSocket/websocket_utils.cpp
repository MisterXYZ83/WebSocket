#include "websocket_utils.h"
#include <stdlib.h>

//callback per il parser; sono comunque SINCRONE (eseguite nel main thread)
int WebSocketHandshake_HeadersComplete(http_parser *pars)
{
	HttpParserUserData *userdata = (HttpParserUserData *)pars->data;
	WebSocketHandshakeInfo *handshake = (WebSocketHandshakeInfo *)userdata->infos;




	return 0;
}

int WebSocketHandshake_HeaderField(http_parser *pars, const char *at, size_t length)
{
	HttpParserUserData *userdata = (HttpParserUserData *)pars->data;
	WebSocketHandshakeInfo *handshake = (WebSocketHandshakeInfo *)userdata->infos;

	if (at)
	{
		userdata->last_field = 0;
		if (_strnicmp(at, "CONNECTION", length) == 0)			userdata->last_field = &handshake->Connection;
		else if (_strnicmp(at, "SEC-WEBSOCKET-KEY", length) == 0)		userdata->last_field = &handshake->WebSocketKey;
		else if (_strnicmp(at, "SEC-WEBSOCKET-VERSION", length) == 0)	userdata->last_field = &handshake->WebSocketVersion;
		else if (_strnicmp(at, "UPGRADE", length) == 0)				userdata->last_field = &handshake->Upgrade;
		else if (_strnicmp(at, "HOST", length) == 0)				userdata->last_field = &handshake->Host;
		else if (_strnicmp(at, "SEC-WEBSOCKET-ACCEPT", length) == 0)		userdata->last_field = &handshake->WebSocketAccept;
	}

	return 0;
}

int WebSocketHandshake_HeaderValue(http_parser *pars, const char *at, size_t length)
{
	HttpParserUserData *userdata = (HttpParserUserData *)pars->data;
	WebSocketHandshakeInfo *handshake = (WebSocketHandshakeInfo *)userdata->infos;

	if (userdata->last_field)
	{
		*userdata->last_field = new char[length + 1];
		memset(*userdata->last_field, 0, length + 1);

		memcpy(*userdata->last_field, at, length);
	}

	return 0;
}

int WebSocketHandshake_HeaderURL(http_parser *pars, const char *at, size_t length)
{
	HttpParserUserData *userdata = (HttpParserUserData *)pars->data;
	WebSocketHandshakeInfo *handshake = (WebSocketHandshakeInfo *)userdata->infos;


	return 0;
}




WebSocketFrame *CreatePongFrame(unsigned char *user_data, LONG64 len, bool masked)
{
	WebSocketFrame *frame = new WebSocketFrame;
	memset(frame, 0, sizeof(WebSocketFrame));

	frame->Final = 1;
	frame->FragmentIndex = 0;
	frame->IsMasked = masked ? 1 : 0;
	frame->OpCode = WEBSOCKET_OPCODE_PONG;
	frame->Reserved1 = 0;
	frame->Reserved2 = 0;
	frame->Reserved3 = 0;
	frame->PayloadLength = 0;
	frame->ExtendedPayloadLength = 0;
	frame->Payload = NULL;

	if (user_data != NULL && len > 0)
	{
		//devo rispondere con i dati inviati
		unsigned char *payload_data = new unsigned char[len];
		memset(payload_data, 0, len);

		memcpy(payload_data, user_data, len);

		if (masked)
		{

			frame->Mask[0] = rand() % 256;
			frame->Mask[1] = rand() % 256;
			frame->Mask[2] = rand() % 256;
			frame->Mask[3] = rand() % 256;

			WebSocketPayloadTransform(payload_data, frame->Mask, len);

			frame->Payload = payload_data;

			if (len <= 125) frame->PayloadLength = len;
			else if (len > 126 && len < 0xFFFF)
			{
				frame->PayloadLength = 126;
				frame->ExtendedPayloadLength = len;
			}
			else if (len > 0xFFFF && len < 0x7FFFFFFFFFFFFFFF)
			{
				frame->PayloadLength = 127;
				frame->ExtendedPayloadLength = len;
			}
			else
			{
				//il pacchetto fa frammentato, ma i control message non possono!
				if (payload_data) delete payload_data;
				delete frame;
				frame = NULL;

				return NULL;
			}

		}

		frame->Payload = payload_data;
	}

	return frame;
}


bool WebSocketPayloadTransform(unsigned char *data, unsigned char *mask, int len)
{
	if (!data || len <= 0) return false;

	int k = 0;

	for (int i = 0; i < len; i++)
	{
		k = i % 4;
		data[i] ^= mask[k];
	}

	return true;
}
