#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

#include "leptjson.h"
#include <assert.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>

#define EXPECT(c, ch)	do { assert(*c->json == (ch)); c->json++; } while(0)

typedef struct {
	const char* stack;
	size_t size, top;
	const char* json;
} lept_context;

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

static void* lept_context_push(lept_context* c, size_t size)
{
	void* ret;
	assert(size > 0);
	if (c->top + size >= c->size)
	{
		if (c->size == 0)
			c->size = LEPT_PARSE_STACK_INIT_SIZE;
		while (c->top + size >= c->size)
			c->size += (c->size >> 1);
		c->stack = (const char*)realloc(c->stack, c->size);
		assert(c->stack != NULL);
	}

	ret = c->stack + c->top;
	c->top += size;
	return ret;
}

static void* lept_context_pop(lept_context* c, size_t size)
{
	assert(c->top >= size);
	return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context* c)
{
	const char* p = c->json;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		p++;
	c->json = p;
}

static int lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type)
{
	EXPECT(c, literal[0]);
	int i;
	for (i = 0; literal[i+1]; i++)
	{
		if (c->json[i] != literal[i+1])
		{
			return LEPT_PARSE_INVALID_VALUE;
		}
	}

	c->json += i;
	v->type = type;
	return LEPT_PARSE_OK;
}

#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')

static int lept_parse_number(lept_context* c, lept_value* v) {
	const char* end;

	/* \TODO validate number */
	end = c->json;

	if (*end == '-') end++;

	if (*end == '0') {
		end++;
	}
	else if(ISDIGIT1TO9(*end))
	{
		end++;
		while (1)
		{
			if (ISDIGIT(*end))
			{
				end++;
				continue;
			}
			else
			{
				break;
			}
		}
	}
	else
	{
		return LEPT_PARSE_INVALID_VALUE;
	}

	if (*end == '.')
	{
		end++;
		if (ISDIGIT(*end))
		{
			end++;
			while (1)
			{
				if (ISDIGIT(*end))
				{
					end++;
					continue;
				}
				else
				{
					break;
				}
			}
		}
		else
		{
			return LEPT_PARSE_INVALID_VALUE;
		}
	}

	if (*end == 'e' || *end == 'E')
	{
		end++;
		if (*end == '+' || *end == '-') end++;
		if (ISDIGIT(*end))
		{
			end++;
			while (1)
			{
				if (ISDIGIT(*end))
				{
					end++;
					continue;
				}
				else
				{
					break;
				}
			}
		}
		else
		{
			return LEPT_PARSE_INVALID_VALUE;
		}
	}

	errno = 0;
	v->u.n = strtod(c->json, NULL);
	if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
	{
		return LEPT_PARSE_NUMBER_TOO_BIG;
	}

	// 没有发生转换，也说明出错了
	// strtod()在没有发生转换时，会返回0，若输入也是0，则混淆了
	// 另外，如果传入的值过于小，strtod()将返回0，这里暂时不考虑此问题？
	c->json = end;
	v->type = LEPT_NUMBER;
	return LEPT_PARSE_OK;
}

#define PUTC(c, ch)  do {*(char *)lept_context_push(c, sizeof(char)) = (ch);} while(0)
static int lept_parse_string(lept_context* c, lept_value* v)
{
	size_t head = c->top, len;
	const char* p;
	EXPECT(c, '"');
	p = c->json;
	while (1)
	{
		char ch = *(p++);
		switch (ch)
		{
		case '"':
			// to the end
			len = c->top - head;
			lept_set_string(v, (const char*)lept_context_pop(c, len), len);
			c->json = p;
			return LEPT_PARSE_OK;
		case '\0':
			// bad string (missing quotation mark)
			c->top = head;
			return LEPT_PARSE_MISS_QUOTATION_MARK;
		case '\\':
			switch (*(p++))
			{
			case '"': PUTC(c, '"'); break;
			case '\\': PUTC(c, '\\'); break;
			case '/':  PUTC(c, '/'); break;
			case 'b':  PUTC(c, '\b'); break;
			case 'f':  PUTC(c, '\f'); break;
			case 'n':  PUTC(c, '\n'); break;
			case 'r':  PUTC(c, '\r'); break;
			case 't':  PUTC(c, '\t'); break;
			default:
				c->top = head;
				return LEPT_PARSE_INVALID_STRING_ESCAPE;
				break;
			}
			break;
		default:
			// normal char
			if ((unsigned char)ch < 0x20)
			{
				c->top = head;
				return LEPT_PARSE_INVALID_STRING_CHAR;
			}
			PUTC(c, ch);
		}
	}
}

// 感觉类似编译器的词法分析器； 状态转换
static int lept_parse_value(lept_context* c, lept_value* v)
{
	switch (*c->json)
	{
	case 'n': return lept_parse_literal(c, v, "null", LEPT_NULL);
	case 't': return lept_parse_literal(c, v, "true", LEPT_TRUE);
	case 'f': return lept_parse_literal(c, v, "false", LEPT_FALSE);
	case '"': return lept_parse_string(c, v);
	default: return lept_parse_number(c, v);
	case '\0': return LEPT_PARSE_EXPECT_VALUE;
	// default: return LEPT_PARSE_INVALID_VALUE;
	}
}

int lept_parse(lept_value* v, const char* json)
{
	assert(v != NULL);
	lept_context c;
	c.json = json;
	c.stack = NULL;
	c.size = 0;
	c.top = 0;

	lept_init(v);
	lept_parse_whitespace(&c);
	int lept_parse_ret	= lept_parse_value(&c, v);
	if (lept_parse_ret == LEPT_PARSE_OK)
	{
		lept_parse_whitespace(&c);
		if (c.json[0] != '\0')
		{
			lept_parse_ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
			v->type = LEPT_NULL;
		}
	}
	assert(c.top == 0);
	free(c.stack); // 若stack为null，free() does nothing
	
	return lept_parse_ret;
}

void lept_free(lept_value* v)
{
	assert(v != NULL);
	if (v->type == LEPT_STRING)
		free(v->u.s.s);
	v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value* v)
{
	assert(v != NULL);
	return v->type;
}

double lept_get_number(const lept_value* v)
{
	assert(v != NULL && v->type == LEPT_NUMBER);
	return v->u.n;
}

void lept_set_number(lept_value* v, double n)
{
	assert(v != NULL);
	lept_free(v);
	v->u.n = n;
	v->type = LEPT_NUMBER;
}

int lept_get_boolean(const lept_value* v)
{
	assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
	return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b) {
	assert(v != NULL);
	lept_free(v);
	v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

const char* lept_get_string(const lept_value* v)
{
	assert(v != NULL && v->type == LEPT_STRING);
	return v->u.s.s;
}

size_t lept_get_string_length(const lept_value* v)
{
	assert(v != NULL && v->type == LEPT_STRING);
	return v->u.s.len;
}

void lept_set_string(lept_value* v, const char* s, size_t len)
{
	assert(v != NULL && (s != NULL || len == 0));
	lept_free(v);
	v->u.s.s = (char*)malloc(len + 1);
	assert(v->u.s.s != NULL); // malloc 出错直接终止程序
	memcpy(v->u.s.s, s, len);
	v->u.s.s[len] = '\0';
	v->u.s.len = len;
	v->type = LEPT_STRING;
}
