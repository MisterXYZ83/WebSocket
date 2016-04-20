#include "websocket.h"
#include "websocket_utils.h"
#include <stdlib.h>
#include <string.h>
#include "http_parser.h"



unsigned long WebSocketFrameElement::FragmentCounter = 0;

DWORD WINAPI WebSocketServer::WSSTranceiverThread(void *data)
{
	WebSocketTranceiver *tranceiver = (WebSocketTranceiver *)data;
	WebSocketServer *thiz = tranceiver->WSServer;

	if (!data) return 0;

	//ricezione dati
	char *receiver_buffer = 0;

	int received = 0;
	bool end_rec = false;
	int n_realloc = 1;

	while ( 1 )
	{
		//carico dati fino a che ci sono
		//prealloco il buffer, sara' deallocato dal consumatore!
		receiver_buffer = new char[RECV_BUFFER_SIZE+1];
		memset(receiver_buffer, 0, RECV_BUFFER_SIZE+1);
		received = 0;

		do
		{
			received += recv(tranceiver->TranceiverSocket, receiver_buffer + received, RECV_BUFFER_SIZE, 0);

			printf("MESSAGE: ");
			for (int k = 0; k < received; k++) printf("%02X ", (unsigned char)receiver_buffer[k]);
			printf("\r\n\r\n");

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
			PostMessage(tranceiver->WSServer->mMessageWindow, WSS_RECEIVER_NEW_DATA, (WPARAM)received, (LPARAM)receiver_buffer);
			
		}
		else
		{
			//errore, invio
			PostMessage(tranceiver->WSServer->mMessageWindow, WSS_RECEIVER_ERROR, 0, 0);
			return 0;
		}
		
	}

}

int WebSocketServer::WSSParseHandshake(WebSocketTranceiver *tc, char *data, int size)
{
	//parsing dell'handshake http
	if (!tc || !data || size <= 0) return -1;

	//utilizzo un parser http C da internet (improponibile il parsing completo....sono troppo pigro!)
	//riferimento in "4.2.1 Reading the Client's Opening Handshake"

	/*
	1.  An HTTP / 1.1 or higher GET request, including a "Request-URI"[RFC2616] that should be interpreted as a / resource name / defined in Section 3 (or an absolute HTTP / HTTPS URI containing the / resource name / ).
	2.  A |Host| header field containing the server's authority.
	3.  An |Upgrade| header field containing the value "websocket", treated as an ASCII case-insensitive value.
	4.  A |Connection| header field that includes the token "Upgrade", treated as an ASCII case-insensitive value.
	5.  A |Sec-WebSocket-Key| header field with a base64 - encoded(see Section 4 of[RFC4648]) value that, when decoded, is 16 bytes in length.
	6.  A |Sec-WebSocket-Version| header field, with a value of 13.
	7.  Optionally, an |Origin| header field.This header field is sent by all browser clients.A connection attempt lacking this header field SHOULD NOT be interpreted as coming from a browser client.
	8.  Optionally, a |Sec-WebSocket-Protocol| header field, with a list of values indicating which protocols the client would like to speak, ordered by preference.
	9.  Optionally, a |Sec-WebSocket-Extensions| header field, with a list of values indicating which extensions the client would like to speak.The interpretation of this header field is discussed in Section 9.1.
	10. Optionally, other header fields, such as those used to send cookies or request authentication to a server. Unknown header fields are ignored, as per[RFC2616].
	*/

	printf("HEADER:\r\n%s\r\n\r\n", data);

	http_parser_settings parser_settings;
	http_parser parser;

	http_parser_settings_init(&parser_settings);
	http_parser_init(&parser, HTTP_REQUEST);	//dobbiamo parsare una REQUEST

	parser_settings.on_headers_complete = WebSocketHandshake_HeadersComplete;
	parser_settings.on_header_field = WebSocketHandshake_HeaderField;
	parser_settings.on_header_value = WebSocketHandshake_HeaderValue;
	parser_settings.on_url = WebSocketHandshake_HeaderURL;

	tc->HandshakeInfos->HttpParser = &parser;
	
	HttpParserUserData *ud = new HttpParserUserData;
	ud->infos = tc->HandshakeInfos;
	ud->last_field = 0;

	parser.data = (void *)ud;
	
	http_parser_execute(&parser, &parser_settings, data, size);

	//terminato il parsing (parsing sincrono su main thread), struttura handshake riempita
	//verifico validita' campi
	delete ud;
	ud = 0;

	//verifica dei campi dell'header

	//check method == GET
	
	if (parser.method != HTTP_GET) return -1;

	//versione http == 1.1
	if (parser.http_minor != 1 || parser.http_major != 1) return -1;


	//verifico i campi dell'header
	bool invalid_field = false;

	if (!mTranceiver->HandshakeInfos->Connection || _strnicmp(mTranceiver->HandshakeInfos->Connection, "UPGRADE", sizeof("UPGRADE"))) invalid_field = true;
	if (!mTranceiver->HandshakeInfos->Host) invalid_field = true;
	if (!mTranceiver->HandshakeInfos->WebSocketVersion || _strnicmp(mTranceiver->HandshakeInfos->WebSocketVersion, "13", sizeof("13"))) invalid_field = true;
	if (!mTranceiver->HandshakeInfos->Upgrade || _strnicmp(mTranceiver->HandshakeInfos->Upgrade, "WEBSOCKET", sizeof("WEBSOCKET"))) invalid_field = true;
	if (!mTranceiver->HandshakeInfos->WebSocketKey ) invalid_field = true;


	return 0;


}


//analizzatore di frame
#define BYTE unsigned char

WebSocketFrame *WebSocketServer::WSSDecodeFrame(WebSocketTranceiver *tc, char *data, int size)
{
	//decodifica del header websocket
	WebSocketFrame *frame = NULL;

	if (tc == NULL || data == NULL || size <= 0) return frame;

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

	frame->OwnerTranceiver = tc;

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

	if ( frame->IsMasked ) WebSocketPayloadTransform(frame->Payload, frame->Mask, total_payload_len);

	return frame;
}

bool WebSocketServer::WSSParseMessage(WebSocketTranceiver *tc, WebSocketFrame *actual_frame)
{
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

		PostMessage(mMessageWindow, WSS_RECEIVED_OPEN_FRAGMENT, 0, 0);

		return true;
	}

	//N: (frammenti intermedi) // 3: finale
	if (tc->FragmentedTransferActive && actual_frame->IsContinuationFrame() && tc->FramedMessage )
	{
		WebSocketFrameElement *elem = new WebSocketFrameElement;

		WebSocketFrameElement *head = tc->FramedMessage;

		elem->Frame = actual_frame;
		elem->Frame->FragmentIndex = WebSocketFrameElement::FragmentCounter;
		
		elem->NextFrame = NULL;
		elem->PreviousFrame = head->PreviousFrame;
		
		head->PreviousFrame->NextFrame = elem;

		tc->FragmentedTransferActive = !actual_frame->Final;

		if (actual_frame->Final) PostAppMessage(mMessageWindow, WSS_RECEIVED_CLOSE_FRAGMENT, 0, 0);

		return true;
	}

	//frame singolo (non frammentato)
	if (!tc->FragmentedTransferActive && actual_frame->Final && !actual_frame->IsContinuationFrame())
	{
		//check se e' di controllo
		if (actual_frame->IsControlFrame())
		{
			PostMessage(mMessageWindow, WSS_RECEIVED_CONTROL_MESSAGE, 0, (LPARAM)actual_frame);
		}
		else if (actual_frame->IsNonControlFrame())
		{
			PostMessage(mMessageWindow, WSS_RECEIVED_DATA_MESSAGE, 0, (LPARAM)actual_frame);
		}
	}

	return false;
}

bool WebSocketServer::WSSSendFrame(WebSocketTranceiver *tc, WebSocketFrame *frame)
{
	//creo il pacchetto
	unsigned char *data_to_send = NULL;
	LONG64 total_len = 2;

	if (!tc || !frame) return false;

	//la dim del pacchetto totale e' data da 2 + (2/8 in base al payload len) + (0/4 in base a masked) + payload_len
	
	if (frame->PayloadLength <= 125) total_len += frame->PayloadLength;
	else if ( frame->PayloadLength == 126 ) total_len += 2 + frame->ExtendedPayloadLength;
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
		pos += send(mTranceiver->TranceiverSocket, (char *)data_to_send + pos, total_len - pos, 0);

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


//////////////////////////////
//codice vecchio

/*
int old_WSSParseHandshake(WebSocketTranceiver *tc, char *data, int size)
{
	//parsing dell'handshake http
	if (!tc || !data || size <= 0) return -1;

	//utilizzo un parser http C da internet (improponibile il parsing completo....sono troppo pigro!)
	//riferimento in "4.2.1 Reading the Client's Opening Handshake"

	printf("HEADER:\r\n%s\r\n\r\n", data);

	RequestHeader *header = NULL;
	header = h3_request_header_new();

	int ret = h3_request_header_parse(header, data, size);

	if (ret)
	{
		h3_request_header_free(header);
		return -1;
	}

	//verifica dei campi dell'header
	char *method = NULL;
	char *host = NULL;
	char *upgrade = NULL;
	char *connection = NULL;
	char *ws_key = NULL;
	char *ws_version = NULL;
	char *http_version = NULL;
	char *request_uri = NULL;

	//check method == GET
	method = (char *)malloc(header->RequestMethodLen);
	memcpy(method, header->RequestMethod, header->RequestMethodLen);

	if (_strnicmp(method, "GET", header->RequestMethodLen))
	{
		free(method);
		h3_request_header_free(header);
		return -1;
	}

	//versione http
	if (header->HTTPVersionLen - 5 <= 0)
	{
		free(method);

		h3_request_header_free(header);
		return -1;
	}

	http_version = (char *)malloc((header->HTTPVersionLen - 5));
	memcpy(http_version, header->HTTPVersion + 5, (header->HTTPVersionLen - 5));

	float http_version_f = atof(http_version);

	if (http_version_f < 1.1)
	{
		free(http_version);
		free(method);

		h3_request_header_free(header);
		return -1;
	}

	//salvo il request uri, sara analizzato successivamente
	request_uri = (char *)malloc(header->RequestURILen);
	memcpy(request_uri, header->RequestURI, header->RequestURILen);

	//verifico i campi dell'header
	int idx = 0;
	int n_fields = header->HeaderSize;
	bool invalid_field = false;

	while (idx < n_fields)
	{
		HeaderField field = header->Fields[idx];

		if (!_strnicmp(field.FieldName, "HOST", field.FieldNameLen) && field.ValueLen > 0)
		{
			//campo host
			host = (char *)malloc(field.ValueLen + 1);
			memset(host, 0, field.ValueLen + 1);
			memcpy(host, field.Value, field.ValueLen);
		}
		else if (!_strnicmp(field.FieldName, "UPGRADE", field.FieldNameLen))
		{
			//upgrade
			upgrade = (char *)malloc(field.ValueLen + 1);
			memset(upgrade, 0, field.ValueLen + 1);
			memcpy(upgrade, field.Value, field.ValueLen);

			//verifico se il valore sia pari a "websocket"
			if (_strnicmp(upgrade, "websocket", field.ValueLen))
			{
				invalid_field = true;
				break;
			}
		}
		else if (!_strnicmp(field.FieldName, "CONNECTION", field.FieldNameLen))
		{
			//connection
			connection = (char *)malloc(field.ValueLen + 1);
			memset(connection, 0, field.ValueLen + 1);
			memcpy(connection, field.Value, field.ValueLen);

			//verifico se il valore sia pari a "upgrade"
			if (_strnicmp(connection, "upgrade", field.ValueLen))
			{
				invalid_field = true;
				break;
			}
		}
		else if (!_strnicmp(field.FieldName, "SEC-WEBSOCKET-KEY", field.FieldNameLen))
		{
			//websocket key
			ws_key = (char *)malloc(field.ValueLen + 1);
			memset(ws_key, 0, field.ValueLen + 1);
			memcpy(ws_key, field.Value, field.ValueLen);
		}
		else if (!_strnicmp(field.FieldName, "SEC-WEBSOCKET-VERSION", field.FieldNameLen))
		{
			//websocket version
			ws_version = (char *)malloc(field.ValueLen + 1);
			memset(ws_version, 0, field.ValueLen + 1);
			memcpy(ws_version, field.Value, field.ValueLen);

			//verifico se il valore sia pari a "upgrade"
			if (_strnicmp(ws_version, "13", field.ValueLen))
			{
				invalid_field = true;
				break;
			}
		}

		idx++;
	}

	if (!ws_key || !ws_version || !connection || !upgrade || !host) invalid_field = true;

	//verifico se tutti i campi obbligatori sono stati impostati
	if (invalid_field)
	{
		//libero tutte le risorse
		if (host) free(host);
		if (connection) free(connection);
		if (ws_version) free(ws_version);
		if (ws_key) free(ws_key);
		if (upgrade) free(upgrade);
		if (method) free(method);
		if (request_uri) free(request_uri);
		if (http_version) free(http_version);

		//esco
		h3_request_header_free(header);
		return -1;
	}

	//tutti i campi obbligatori sono stati ricevuti
	//con valori corretti, salvo nella sessione i dati utili
	tc->RequestUri = _strdup(request_uri);
	tc->WebSocketKey = _strdup(ws_key);

	if (host) free(host);
	if (connection) free(connection);
	if (ws_version) free(ws_version);
	if (ws_key) free(ws_key);
	if (upgrade) free(upgrade);
	if (method) free(method);
	if (request_uri) free(request_uri);
	if (http_version) free(http_version);

	//libero il parser
	h3_request_header_free(header);

	return 0;

}
*/