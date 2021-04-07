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
#include <ctype.h>

#define EXPECT(c, ch)	do { assert(*c->json == (ch)); c->json++; } while(0)

#define PUTC(c, ch)  do {*(char *)lept_context_push(c, sizeof(char)) = (ch);} while(0)
#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

typedef struct {
	char* stack;
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
		char * char_p = (char*)realloc(c->stack, c->size);
		assert(char_p != NULL);
		c->stack = char_p;
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

static const char* lept_parse_hex4(const char* p, unsigned* u)
{
	*u = 0;
	for (int i = 0; i < 4; i++)
	{
		char ch = *p++;
		*u <<= 4;
		if (ch >= '0' && ch <= '9') *u |= ch - '0';
		else if (ch >= 'A' && ch <= 'F') *u |= ch - 'A' + 10;
		else if (ch >= 'a' && ch <= 'f') *u |= ch - 'a' + 10;
		else return NULL;
	}
	return p;
}

static void  lept_encode_utf8(lept_context* c, unsigned u)
{
	// 先将高位压入栈？怎么取数然后解码呢？
	// 不应该是高位置于栈顶，然后才能根据编码规则实现解码？
	if (u <= 0x7F)
		PUTC(c, u & 0xFF);
	else if (u <= 0x7FF) {
		PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
		PUTC(c, 0x80 | (u & 0x3F));
	}
	else if (u <= 0xFFFF) {
		PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
		PUTC(c, 0x80 | ((u >> 6) & 0x3F));
		PUTC(c, 0x80 | (u & 0x3F));
	}
	else {
		assert(u <= 0x10FFFF);
		PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
		PUTC(c, 0x80 | ((u >> 12) & 0x3F));
		PUTC(c, 0x80 | ((u >> 6) & 0x3F));
		PUTC(c, 0x80 | (u & 0x3F));
	}
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

/* 解析 JSON 字符串，把结果写入 str 和 len */
/* str 指向 c->stack 中的元素，需要在 c->stack  */
static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
	/* \todo */
	EXPECT(c, '"');
	unsigned u;
	size_t head = c->top;
	const char* p;
	p = c->json;
	while (1)
	{
		char ch = *(p++);
		switch (ch)
		{
		case '"':
			// to the end
			*len = c->top - head;
			*str = (char*)lept_context_pop(c, *len);
			c->json = p;
			return LEPT_PARSE_OK;
		case '\0':
			// bad string (missing quotation mark)
			/*c->top = head;
			return LEPT_PARSE_MISS_QUOTATION_MARK;*/
			STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
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
			case 'u':
				p = lept_parse_hex4(p, &u);
				if (p == NULL)
					STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
				if (0xD800 <= u && 0xDBFF >= u)  // surrogate pair
				{
					if (*(p++) != '\\')
					{
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
					}
					if (*(p++) != 'u')
					{
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
					}
					unsigned u2;
					p = lept_parse_hex4(p, &u2);
					if (p == NULL)
					{
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
					}
					if (0xDC00 > u2 || 0xDFFF < u2)
					{
						STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
					}
					// codepoint = 0x1000 + (H - 0xD800) * 0x400 + (L - 0xDC00)
					u = 0x10000 + ((u - 0xD800) << 10) + (u2 - 0xDC00);
				}
				lept_encode_utf8(c, u);
				break;
			default:
				/*c->top = head;
				return LEPT_PARSE_INVALID_STRING_ESCAPE;*/
				STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
				break;
			}
			break;
		default:
			// normal char
			if ((unsigned char)ch < 0x20)
			{
				// c->top = head;
				// return LEPT_PARSE_INVALID_STRING_CHAR;
				STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
			}
			PUTC(c, ch);
		}
	}
}

static int lept_parse_string(lept_context* c, lept_value* v)
{
	int ret;
	char* s;
	size_t len;
	if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK)
		lept_set_string(v, s, len);
	return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v); /* 前向声明 */

static int lept_parse_array(lept_context* c, lept_value* v)
{
	size_t size = 0;
	int ret;

	EXPECT(c, '[');
	lept_parse_whitespace(c);
	if (*c->json == ']')
	{
		c->json++;
		v->u.a.e = NULL;
		v->u.a.size = 0;
		v->type = LEPT_ARRAY;
		return LEPT_PARSE_OK;
	}

	while (1)
	{
		lept_value e; // 临时结点
		lept_init(&e);
		if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK)
			break;
		size++;
		memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
		// lept_free(&e); // 释放为临时lept_value e分配的内存空间
		// 然而不需要这个，因为memcpy实际上copy的是lept_value，而lept_value中放的都是指针
		// 如果调用了，才会出问题呢，不调用才是正确的

		lept_parse_whitespace(c);
		if (*c->json == ',')
		{
			c->json++;
			lept_parse_whitespace(c);
			continue;
		}
		else if (*c->json == ']')
		{
			c->json++;
			v->u.a.e = (lept_value*)malloc(size * sizeof(lept_value));
			memcpy(v->u.a.e, (lept_value*)lept_context_pop(c, size * sizeof(lept_value)), size * sizeof(lept_value));
			v->u.a.size = size;
			v->type = LEPT_ARRAY;
			return LEPT_PARSE_OK;
		}
		else
		{
			ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
			break;
		}
	}

	/* Pop and free values on the stack */
	for (int i = 0; i < size; i++)
		lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
	v->type = LEPT_NULL;;
	return ret;
}

static int lept_parse_object(lept_context* c, lept_value* v)
{
	EXPECT(c, '{');
	lept_parse_whitespace(c);
	if (*c->json == '}')
	{
		c->json++;
		v->u.o.m = NULL;
		v->u.o.size = 0;
		v->type = LEPT_OBJECT;
		return LEPT_PARSE_OK;
	}
	size_t size = 0;
	int ret;
	char* temp_member_key;
	lept_member m;

	while (1)
	{
		m.k = NULL;
		lept_init(&m.v);

		// resolve the key
		if (*c->json != '"')
		{
			ret = LEPT_PARSE_MISS_KEY;
			break;
		}
		if ((ret = lept_parse_string_raw(c, &temp_member_key, &m.klen)) != LEPT_PARSE_OK)
		{
			break;
		}
		m.k = (char*)malloc(m.klen + 1);
		assert(m.k != NULL);
		memcpy(m.k, temp_member_key, m.klen);
		m.k[m.klen] = '\0';
		lept_parse_whitespace(c);

		// resolve the colon(':')
		if (*c->json != ':')
		{
			ret = LEPT_PARSE_MISS_COLON;
			break;
		}
		else
		{
			c->json++;
			lept_parse_whitespace(c);
		}

		// resolve the value
		if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK)
		{
			break;
		}
		size++;
		memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
		m.k = NULL;
		lept_parse_whitespace(c);

		if (*c->json == ',')
		{
			c->json++;
			lept_parse_whitespace(c);
			continue;
		}
		else if (*c->json == '}')
		{
			c->json++;
			v->u.o.size = size;
			v->u.o.m = (lept_member*)malloc(size * sizeof(lept_member));
			memcpy(v->u.o.m, lept_context_pop(c, size * sizeof(lept_member)), size * sizeof(lept_member));
			v->type = LEPT_OBJECT;
			return LEPT_PARSE_OK;
		}
		else
		{
			ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
			break;
		}
	}

	/* Pop and free values on the stack */
	free(m.k);
	lept_member* temp_lept_member = (lept_member*)lept_context_pop(c, size*sizeof(lept_member));
	for (int i = 0; i < size; i++)
	{
		lept_free(&(temp_lept_member[i].v));
		free(temp_lept_member[i].k);
	}
	v->type = LEPT_NULL;
	return ret;
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
	case '[': return lept_parse_array(c, v);
	case '{': return lept_parse_object(c, v);
	case '\0': return LEPT_PARSE_EXPECT_VALUE;
	default: return lept_parse_number(c, v);
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
	else if (v->type == LEPT_ARRAY)
	{
		size_t size = v->u.a.size;
		for (int i = 0; i < size; i++)
		{
			lept_free(v->u.a.e + i);
		}
		free(v->u.a.e);
	}
	else if (v->type == LEPT_OBJECT)
	{
		size_t size = v->u.o.size;
		for (int i = 0; i < size; i++)
		{
			lept_free(&(v->u.o.m[i].v));
			free(v->u.o.m[i].k);
		}
		free(v->u.o.m);
	}
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

size_t lept_get_array_size(const lept_value* v)
{
	assert(v != NULL && v->type == LEPT_ARRAY);
	return v->u.a.size;
}

lept_value* lept_get_array_element(const lept_value* v, size_t index)
{
	assert(v != NULL && v->type == LEPT_ARRAY);
	assert(index >= 0 && index < v->u.a.size);
	// return v->u.a.e + index;
	return &(v->u.a.e[index]);
}

size_t lept_get_object_size(const lept_value* v)
{
	assert(v != NULL && v->type == LEPT_OBJECT);
	return v->u.o.size;
}

const char* lept_get_object_key(const lept_value* v, size_t index)
{

	assert(v != NULL && v->type == LEPT_OBJECT);
	assert(index >= 0 && index < v->u.o.size);
	// return v->u.a.e + index;
	return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index)
{
	assert(v != NULL && v->type == LEPT_OBJECT);
	assert(index >= 0 && index < v->u.o.size);
	// return v->u.a.e + index;
	return v->u.o.m[index].klen;
}

lept_value* lept_get_object_value(const lept_value* v, size_t index)
{
	assert(v != NULL && v->type == LEPT_OBJECT);
	assert(index >= 0 && index < v->u.o.size);
	// return v->u.a.e + index;
	return &(v->u.o.m[index].v);
}
