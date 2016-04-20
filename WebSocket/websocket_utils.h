#pragma once
#include "websocket.h"

///////////////// Funzioni SHA-1 

#define uchar unsigned char 
#define uint unsigned int 


typedef struct {
	uchar data[64];
	uint datalen;
	uint bitlen[2];
	uint state[5];
	uint k[4];
} SHA1_CTX;


void sha1_transform(SHA1_CTX *ctx, uchar data[]);
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, uchar data[], uint len);
void sha1_final(SHA1_CTX *ctx, uchar hash[]);


/////////// BASE64

int Base64decode_len(const char *bufcoded);
int Base64decode(char *bufplain, const char *bufcoded);
int Base64encode_len(int len);
int Base64encode(char *encoded, const char *string, int len);


/////////// Masking

struct HttpParserUserData
{
	char **last_field;

	WebSocketHandshakeInfo *infos;
};

int WebSocketHandshake_HeadersComplete(http_parser *pars);
int WebSocketHandshake_HeaderField(http_parser *pars, const char *at, size_t length);
int WebSocketHandshake_HeaderValue(http_parser *pars, const char *at, size_t length);
int WebSocketHandshake_HeaderURL(http_parser *pars, const char *at, size_t length);

bool WebSocketPayloadTransform(unsigned char *data, unsigned char *mask, int len);
WebSocketFrame *CreatePongFrame(unsigned char *user_data, LONG64 len, bool masked);