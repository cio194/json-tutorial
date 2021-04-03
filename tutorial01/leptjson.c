#include "leptjson.h"
#include <assert.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>

#define EXPECT(c, ch)	do { assert(*c->json == (ch)); c->json++; } while(0)

typedef struct {
	const char* json;
} lept_context;

static void lept_parse_whitespace(lept_context* c)
{
	const char* p = c->json;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		p++;
	c->json = p;
}

//static int lept_parse_null(lept_context* c, lept_value* v)
//{
//	EXPECT(c, 'n');
//	if (c->json[0] != 'u' || c->json[1] != 'l' || c->json[2] != 'l')
//		return LEPT_PARSE_INVALID_VALUE;
//	c->json += 3;
//	v->type = LEPT_NULL;
//	return LEPT_PARSE_OK;
//}
//
//static int lept_parse_true(lept_context* c, lept_value* v)
//{
//	EXPECT(c, 't');
//	if (c->json[0] != 'r' || c->json[1] != 'u' || c->json[2] != 'e')
//		return LEPT_PARSE_INVALID_VALUE;
//	c->json += 3;
//	v->type = LEPT_TRUE;
//	return LEPT_PARSE_OK;
//}
//
//static int lept_parse_false(lept_context* c, lept_value* v)
//{
//	EXPECT(c, 'f');
//	if (c->json[0] != 'a' || c->json[1] != 'l' || c->json[2] != 's' || c->json[3] != 'e')
//		return LEPT_PARSE_INVALID_VALUE;
//	c->json += 4;
//	v->type = LEPT_FALSE;
//	return LEPT_PARSE_OK;
//}

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
	v->n = strtod(c->json, NULL);
	if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL))
	{
		return LEPT_PARSE_NUMBER_TOO_BIG;
	}

	// û�з���ת����Ҳ˵��������
	// strtod()��û�з���ת��ʱ���᷵��0��������Ҳ��0���������
	// ���⣬��������ֵ����С��strtod()������0��������ʱ�����Ǵ����⣿
	c->json = end;
	v->type = LEPT_NUMBER;
	return LEPT_PARSE_OK;
}


// �о����Ʊ������Ĵʷ��������� ״̬ת��
static int lept_parse_value(lept_context* c, lept_value* v)
{
	switch (*c->json)
	{
	case 'n': return lept_parse_literal(c, v, "null", LEPT_NULL);
	case 't': return lept_parse_literal(c, v, "true", LEPT_TRUE);
	case 'f': return lept_parse_literal(c, v, "false", LEPT_FALSE);
	default: return lept_parse_number(c, v);
	case '\0': return LEPT_PARSE_EXPECT_VALUE;
	// default: return LEPT_PARSE_INVALID_VALUE;
	}
}

int lept_parse(lept_value* v, const char* json)
{
	lept_context c;
	assert(v != NULL);
	c.json = json;
	v->type = LEPT_NULL;
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
	
	return lept_parse_ret;
}

lept_type lept_get_type(const lept_value* v)
{
	assert(v != NULL);
	return v->type;
}

double lept_get_number(const lept_value* v)
{
	assert(v != NULL && v->type == LEPT_NUMBER);
	return v->n;
}