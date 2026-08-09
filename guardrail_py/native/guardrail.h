#ifndef GUARDRAIL_H
#define GUARDRAIL_H
#include <stddef.h>
#ifdef _WIN32
#define GR_API __declspec(dllexport)
#else
#define GR_API
#endif
enum { GR_SECRET=1, GR_INJECTION=2, GR_JSON=4, GR_DEPTH=8 };
typedef struct gr_stream gr_stream;
GR_API gr_stream *gr_create(int json_mode);
GR_API void gr_destroy(gr_stream *stream);
GR_API unsigned gr_feed(gr_stream *stream, const unsigned char *bytes, size_t count);
GR_API unsigned gr_finish(gr_stream *stream);
#endif
