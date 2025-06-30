/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1





# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif


/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 1 "re_grammar.ypp"

#include "parsenode.h"
#include "parsetree.h"
#include "parseutil.h"
#include "pattern.h"
#include "unicode.h"
#include "encoders/utf8.h"

#include <iomanip>
#include <sstream>
#include <stack>
#include <string>
#include <vector>

namespace {
  struct Context {
    const int* Text;
    const int* TextBegin;
    const int* TextEnd;

    int TokenType;

    ParseTree* Tree;

    UnicodeSet USet;

    bool LiteralMode;
    std::stack<uint8_t> Opts;

    template <class... Args>
    ParseNode* add(Args&&... args) {
      return Tree->add(std::forward<Args>(args)...);
    }
  };

  const uint8_t CASED_MASK = 0x01;
  const uint8_t ASCII_MASK = 0x02;

  union YYSTYPE {
    int c;
    ParseNode* node;
    UnicodeSet* s;
  };

  struct YYLTYPE {
    int first_line; // unused
    int first_column;
    int last_line;  // unused
    int last_column;
  };

  struct ParseError {
    enum {
      NONATOMIC_REPETITON,
      REVERSED_REPETITION_BOUNDS,
      INVALID_ESCAPE,
      UNMATCHED_PARENTHESIS,
      UNMATCHED_BRACKET,
      EMPTY_CHAR_CLASS,
      REVERSED_CHAR_RANGE_BOUNDS,
      REVERSED_BYTE_RANGE_BOUNDS,
      SET_OPERATOR_MISSING_OPERAND
    } Type;

    int Begin;
    int End;
    int First;
    int Second;

    ParseError(
      decltype(Type) type, int begin, int end, int first = -1, int second = -1
    ):
      Type(type), Begin(begin), End(end), First(first), Second(second)
    {}
  };

  static int yylex(YYSTYPE* yylval, YYLTYPE* yylloc, Context* ctx);
  static void yyerror(YYLTYPE* yylloc, Context* ctx, const char* msg);

  void throwError(ParseError e, Context* ctx);
}

#define YYLTYPE_IS_DECLARED 1
#define YYLTYPE_IS_TRIVIAL 1

#define YYDEBUG 0

#if YYDEBUG
extern int yydebug;
#endif

#line 193 "re_grammar.tab.cpp"

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    END = 0,                       /* "end of pattern"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    BYTE = 258,                    /* BYTE  */
    CHAR = 259,                    /* CHAR  */
    DIGIT = 260,                   /* DIGIT  */
    HYPHEN_HYPHEN = 261,           /* HYPHEN_HYPHEN  */
    AMP_AMP = 262,                 /* AMP_AMP  */
    TILDE_TILDE = 263,             /* TILDE_TILDE  */
    TEXT_START = 264,              /* TEXT_START  */
    TEXT_END = 265,                /* TEXT_END  */
    NON_WORD_BOUNDARY = 266,       /* NON_WORD_BOUNDARY  */
    KILL = 267,                    /* KILL  */
    WHACK_SMALL_B = 268,           /* WHACK_SMALL_B  */
    BAD = 269,                     /* "invalid escape"  */
    SET = 270,                     /* SET  */
    UNION = 271,                   /* UNION  */
    INTERSECT = 272,               /* INTERSECT  */
    MINUS = 273,                   /* MINUS  */
    XOR = 274,                     /* XOR  */
    LEAST = 275                    /* LEAST  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */

/* Location type.  */
#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE YYLTYPE;
struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif




int yyparse (Context* ctx);



/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of pattern"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_BYTE = 3,                       /* BYTE  */
  YYSYMBOL_CHAR = 4,                       /* CHAR  */
  YYSYMBOL_DIGIT = 5,                      /* DIGIT  */
  YYSYMBOL_HYPHEN_HYPHEN = 6,              /* HYPHEN_HYPHEN  */
  YYSYMBOL_AMP_AMP = 7,                    /* AMP_AMP  */
  YYSYMBOL_TILDE_TILDE = 8,                /* TILDE_TILDE  */
  YYSYMBOL_TEXT_START = 9,                 /* TEXT_START  */
  YYSYMBOL_TEXT_END = 10,                  /* TEXT_END  */
  YYSYMBOL_NON_WORD_BOUNDARY = 11,         /* NON_WORD_BOUNDARY  */
  YYSYMBOL_KILL = 12,                      /* KILL  */
  YYSYMBOL_WHACK_SMALL_B = 13,             /* WHACK_SMALL_B  */
  YYSYMBOL_BAD = 14,                       /* "invalid escape"  */
  YYSYMBOL_SET = 15,                       /* SET  */
  YYSYMBOL_UNION = 16,                     /* UNION  */
  YYSYMBOL_INTERSECT = 17,                 /* INTERSECT  */
  YYSYMBOL_MINUS = 18,                     /* MINUS  */
  YYSYMBOL_XOR = 19,                       /* XOR  */
  YYSYMBOL_LEAST = 20,                     /* LEAST  */
  YYSYMBOL_21_ = 21,                       /* '-'  */
  YYSYMBOL_22_ = 22,                       /* '|'  */
  YYSYMBOL_23_ = 23,                       /* '('  */
  YYSYMBOL_24_ = 24,                       /* '?'  */
  YYSYMBOL_25_ = 25,                       /* ')'  */
  YYSYMBOL_26_a_ = 26,                     /* 'a'  */
  YYSYMBOL_27_i_ = 27,                     /* 'i'  */
  YYSYMBOL_28_ = 28,                       /* '*'  */
  YYSYMBOL_29_ = 29,                       /* '+'  */
  YYSYMBOL_30_ = 30,                       /* '{'  */
  YYSYMBOL_31_ = 31,                       /* '}'  */
  YYSYMBOL_32_ = 32,                       /* ','  */
  YYSYMBOL_33_ = 33,                       /* '<'  */
  YYSYMBOL_34_ = 34,                       /* '='  */
  YYSYMBOL_35_ = 35,                       /* '!'  */
  YYSYMBOL_36_ = 36,                       /* '^'  */
  YYSYMBOL_37_ = 37,                       /* '$'  */
  YYSYMBOL_38_ = 38,                       /* '.'  */
  YYSYMBOL_39_ = 39,                       /* ']'  */
  YYSYMBOL_40_ = 40,                       /* '['  */
  YYSYMBOL_YYACCEPT = 41,                  /* $accept  */
  YYSYMBOL_regexp = 42,                    /* regexp  */
  YYSYMBOL_alt = 43,                       /* alt  */
  YYSYMBOL_concat = 44,                    /* concat  */
  YYSYMBOL_switch = 45,                    /* switch  */
  YYSYMBOL_switches_on = 46,               /* switches_on  */
  YYSYMBOL_switch_on = 47,                 /* switch_on  */
  YYSYMBOL_switches_off = 48,              /* switches_off  */
  YYSYMBOL_switch_off = 49,                /* switch_off  */
  YYSYMBOL_rep = 50,                       /* rep  */
  YYSYMBOL_number = 51,                    /* number  */
  YYSYMBOL_atom = 52,                      /* atom  */
  YYSYMBOL_53_1 = 53,                      /* $@1  */
  YYSYMBOL_literal = 54,                   /* literal  */
  YYSYMBOL_character = 55,                 /* character  */
  YYSYMBOL_charclass = 56,                 /* charclass  */
  YYSYMBOL_cc_expr_pos = 57,               /* cc_expr_pos  */
  YYSYMBOL_cc_expr_neg = 58,               /* cc_expr_neg  */
  YYSYMBOL_cc_atom = 59,                   /* cc_atom  */
  YYSYMBOL_cc_char_first = 60,             /* cc_char_first  */
  YYSYMBOL_cc_char_not_first = 61,         /* cc_char_not_first  */
  YYSYMBOL_cc_char = 62,                   /* cc_char  */
  YYSYMBOL_cc_named = 63                   /* cc_named  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_uint8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if 1

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* 1 */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL \
             && defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
  YYLTYPE yyls_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE) \
             + YYSIZEOF (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  71
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   727

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  41
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  23
/* YYNRULES -- Number of rules.  */
#define YYNRULES  142
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  183

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   275


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    35,     2,     2,    37,     2,     2,     2,
      23,    25,    28,    29,    32,    21,    38,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      33,    34,     2,    24,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    40,     2,    39,    36,     2,     2,    26,     2,     2,
       2,     2,     2,     2,     2,    27,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    30,    22,    31,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   139,   139,   146,   147,   151,   158,   159,   163,   167,
     174,   175,   176,   180,   181,   185,   189,   196,   197,   201,
     205,   212,   213,   217,   221,   225,   229,   233,   250,   254,
     258,   262,   266,   270,   290,   294,   302,   302,   307,   317,
     321,   325,   329,   333,   360,   387,   392,   397,   408,   419,
     423,   427,   444,   448,   457,   463,   469,   473,   474,   475,
     479,   483,   487,   491,   495,   499,   503,   507,   511,   518,
     537,   588,   598,   608,   618,   628,   638,   648,   658,   668,
     678,   688,   698,   708,   718,   728,   738,   748,   758,   768,
     778,   788,   798,   808,   812,   818,   824,   830,   836,   853,
     859,   876,   882,   883,   888,   896,   902,   908,   914,   920,
     924,   941,   947,   964,   970,   971,   976,   981,   989,   993,
     997,  1001,  1005,  1009,  1010,  1011,  1015,  1019,  1023,  1027,
    1031,  1035,  1039,  1043,  1047,  1051,  1055,  1059,  1063,  1067,
    1071,  1075,  1082
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if 1
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of pattern\"", "error", "\"invalid token\"", "BYTE", "CHAR",
  "DIGIT", "HYPHEN_HYPHEN", "AMP_AMP", "TILDE_TILDE", "TEXT_START",
  "TEXT_END", "NON_WORD_BOUNDARY", "KILL", "WHACK_SMALL_B",
  "\"invalid escape\"", "SET", "UNION", "INTERSECT", "MINUS", "XOR",
  "LEAST", "'-'", "'|'", "'('", "'?'", "')'", "'a'", "'i'", "'*'", "'+'",
  "'{'", "'}'", "','", "'<'", "'='", "'!'", "'^'", "'$'", "'.'", "']'",
  "'['", "$accept", "regexp", "alt", "concat", "switch", "switches_on",
  "switch_on", "switches_off", "switch_off", "rep", "number", "atom",
  "$@1", "literal", "character", "charclass", "cc_expr_pos", "cc_expr_neg",
  "cc_atom", "cc_char_first", "cc_char_not_first", "cc_char", "cc_named", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-115)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-37)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     384,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,   230,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,   110,    26,    -2,   346,
     384,  -115,   -16,  -115,  -115,  -115,  -115,  -115,    32,   384,
    -115,    14,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,   270,  -115,  -115,  -115,  -115,   150,    24,
    -115,  -115,   422,  -115,  -115,  -115,    -2,    39,    47,    48,
      72,    25,  -115,  -115,    20,   384,   384,   -10,  -115,     0,
       3,  -115,    60,  -115,  -115,  -115,  -115,  -115,  -115,   190,
    -115,    61,  -115,  -115,   460,   498,   536,  -115,  -115,   687,
     308,   346,  -115,  -115,  -115,  -115,    16,  -115,  -115,    35,
    -115,   384,   384,     5,     6,    25,  -115,  -115,  -115,  -115,
    -115,     4,  -115,   574,   612,   650,  -115,  -115,   687,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
      41,  -115,    66,    18,  -115,  -115,     7,    11,  -115,  -115,
      62,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,    67,    19,  -115,  -115,  -115,
    -115,    70,  -115
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,    50,    57,    58,    53,    54,    55,    45,    46,    44,
      43,   142,    62,     0,    59,    60,    63,    64,    65,    66,
      67,    68,    47,    48,    52,    61,     0,     0,     2,     3,
       0,     6,    21,    49,    51,    56,    93,    38,     0,     0,
      72,   104,   123,   124,    78,    75,    81,   141,   119,   127,
     128,   130,   129,   125,   126,   132,   131,   134,   135,   136,
     137,   138,   139,     0,   140,   133,   118,   102,     0,   103,
     120,     1,     0,     8,     9,     7,     5,    30,    28,    29,
       0,     0,    15,    16,     0,     0,     0,     0,    13,     0,
       0,    74,   117,    87,    84,    90,   116,   121,   114,     0,
     109,   115,   122,    71,     0,     0,     0,    69,    94,     0,
       0,     4,    24,    22,    23,    34,     0,    19,    20,     0,
      17,     0,     0,     0,     0,     0,    10,    14,    37,   100,
     101,     0,    73,     0,     0,     0,    70,   105,     0,    80,
      79,    96,    77,    76,    95,    83,    82,    97,    99,    98,
       0,    35,    31,     0,    11,    18,     0,     0,    41,    42,
       0,   112,   113,    89,    88,   107,    86,    85,   106,    92,
      91,   108,   111,   110,    25,    32,     0,    39,    40,    12,
      26,    33,    27
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
    -115,  -115,   -29,    13,   -27,  -115,     8,   -28,  -114,   -25,
     -57,  -115,  -115,  -115,  -115,   -26,  -115,  -115,   -65,  -115,
    -100,    73,  -115
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,    27,    28,    29,    30,    87,    88,   119,   120,    31,
     116,    32,    39,    33,    34,    35,    68,    99,   100,    69,
     101,   102,    36
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      67,    76,    74,   108,    75,   155,   129,   161,    77,   149,
      89,   125,    78,    79,    80,   126,    82,    83,    11,    11,
      72,   151,    72,   115,   151,   128,    71,    72,    72,    72,
     158,   159,   177,    72,   137,    90,   178,    98,   173,   141,
     144,   147,    98,    26,    26,   109,   155,   152,   153,   175,
     181,   117,   118,    81,   121,   122,   123,   124,    82,    83,
     154,   117,   118,   112,   130,    84,    85,    86,   165,   168,
     171,   113,   114,    98,    84,    85,    86,   115,    98,    98,
      98,   131,   138,   148,    74,   111,    75,   179,   117,   118,
     174,   180,   156,   157,   182,   127,   176,   160,     0,    70,
       0,     0,     0,     0,     0,   162,     0,    98,    98,    98,
       0,    40,   172,    41,    42,    43,    44,    45,    46,     0,
       0,     0,     0,    47,     0,    11,     0,     0,     0,     0,
       0,    48,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
      26,   103,     0,    92,    42,    43,   104,   105,   106,     0,
       0,     0,     0,    47,     0,    11,     0,     0,     0,     0,
       0,    96,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    97,    64,    65,   107,
      26,   132,     0,    92,    42,    43,   133,   134,   135,     0,
       0,     0,     0,    47,     0,    11,     0,     0,     0,     0,
       0,    96,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    97,    64,    65,   136,
      26,    37,     0,   -36,   -36,   -36,   -36,   -36,   -36,   -36,
     -36,   -36,     0,   -36,     0,   -36,     0,     0,     0,     0,
       0,   -36,     0,   -36,    38,     0,   -36,   -36,     0,     0,
     -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,
     -36,    91,     0,    92,    42,    43,    93,    94,    95,     0,
       0,     0,     0,    47,     0,    11,     0,     0,     0,     0,
       0,    96,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    97,    64,    65,    37,
      26,   -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,
       0,   -36,     0,   -36,     0,     0,     0,     0,     0,   -36,
       0,   -36,   150,     0,   -36,   -36,     0,     0,   -36,   -36,
     -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,   -36,     1,
       2,     3,     4,     5,     6,     7,     8,     9,    73,    10,
       0,    11,     0,     0,     0,     0,     0,    12,     0,    13,
       0,     0,    14,    15,     0,     0,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,     1,     2,     3,
       4,     5,     6,     7,     8,     9,     0,    10,     0,    11,
       0,     0,     0,     0,     0,    12,     0,    13,     0,     0,
      14,    15,     0,     0,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,     1,     2,     3,     4,     5,
       6,     7,     8,     9,     0,    10,     0,    11,     0,     0,
       0,     0,     0,    12,     0,   110,     0,     0,    14,    15,
       0,     0,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    26,    92,    42,    43,   139,     0,     0,     0,
       0,     0,     0,    47,     0,    11,     0,     0,     0,     0,
       0,    96,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    97,    64,    65,   140,
      26,    92,    42,    43,     0,   142,     0,     0,     0,     0,
       0,    47,     0,    11,     0,     0,     0,     0,     0,    96,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    97,    64,    65,   143,    26,    92,
      42,    43,     0,     0,   145,     0,     0,     0,     0,    47,
       0,    11,     0,     0,     0,     0,     0,    96,    49,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,    60,
      61,    62,    97,    64,    65,   146,    26,    92,    42,    43,
     163,     0,     0,     0,     0,     0,     0,    47,     0,    11,
       0,     0,     0,     0,     0,    96,    49,    50,    51,    52,
      53,    54,    55,    56,    57,    58,    59,    60,    61,    62,
      97,    64,    65,   164,    26,    92,    42,    43,     0,   166,
       0,     0,     0,     0,     0,    47,     0,    11,     0,     0,
       0,     0,     0,    96,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    97,    64,
      65,   167,    26,    92,    42,    43,     0,     0,   169,     0,
       0,     0,     0,    47,     0,    11,     0,     0,     0,     0,
       0,    96,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    60,    61,    62,    97,    64,    65,   170,
      26,    42,    43,     0,     0,     0,     0,     0,     0,     0,
      47,     0,    11,     0,     0,     0,     0,     0,     0,    49,
      50,    51,    52,    53,    54,    55,    56,    57,    58,    59,
      60,    61,    62,    97,    64,    65,     0,    26
};

static const yytype_int16 yycheck[] =
{
      26,    30,    29,    68,    29,   119,     3,     3,    24,   109,
      39,    21,    28,    29,    30,    25,    26,    27,    15,    15,
      22,     5,    22,     5,     5,    25,     0,    22,    22,    22,
      25,    25,    25,    22,    99,    21,    25,    63,   138,   104,
     105,   106,    68,    40,    40,    21,   160,    31,    32,    31,
      31,    26,    27,    21,    34,    35,    85,    86,    26,    27,
      25,    26,    27,    24,    90,    33,    34,    35,   133,   134,
     135,    24,    24,    99,    33,    34,    35,     5,   104,   105,
     106,    21,    21,   109,   111,    72,   111,    25,    26,    27,
      24,    24,   121,   122,    24,    87,   153,   125,    -1,    26,
      -1,    -1,    -1,    -1,    -1,   131,    -1,   133,   134,   135,
      -1,     1,   138,     3,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    13,    -1,    15,    -1,    -1,    -1,    -1,
      -1,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,     1,    -1,     3,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    13,    -1,    15,    -1,    -1,    -1,    -1,
      -1,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,     1,    -1,     3,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    13,    -1,    15,    -1,    -1,    -1,    -1,
      -1,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,     1,    -1,     3,     4,     5,     6,     7,     8,     9,
      10,    11,    -1,    13,    -1,    15,    -1,    -1,    -1,    -1,
      -1,    21,    -1,    23,    24,    -1,    26,    27,    -1,    -1,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,     1,    -1,     3,     4,     5,     6,     7,     8,    -1,
      -1,    -1,    -1,    13,    -1,    15,    -1,    -1,    -1,    -1,
      -1,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,     1,
      40,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      -1,    13,    -1,    15,    -1,    -1,    -1,    -1,    -1,    21,
      -1,    23,    24,    -1,    26,    27,    -1,    -1,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,     3,
       4,     5,     6,     7,     8,     9,    10,    11,    12,    13,
      -1,    15,    -1,    -1,    -1,    -1,    -1,    21,    -1,    23,
      -1,    -1,    26,    27,    -1,    -1,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,     3,     4,     5,
       6,     7,     8,     9,    10,    11,    -1,    13,    -1,    15,
      -1,    -1,    -1,    -1,    -1,    21,    -1,    23,    -1,    -1,
      26,    27,    -1,    -1,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,     3,     4,     5,     6,     7,
       8,     9,    10,    11,    -1,    13,    -1,    15,    -1,    -1,
      -1,    -1,    -1,    21,    -1,    23,    -1,    -1,    26,    27,
      -1,    -1,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,     3,     4,     5,     6,    -1,    -1,    -1,
      -1,    -1,    -1,    13,    -1,    15,    -1,    -1,    -1,    -1,
      -1,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,     3,     4,     5,    -1,     7,    -1,    -1,    -1,    -1,
      -1,    13,    -1,    15,    -1,    -1,    -1,    -1,    -1,    21,
      22,    23,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,     3,
       4,     5,    -1,    -1,     8,    -1,    -1,    -1,    -1,    13,
      -1,    15,    -1,    -1,    -1,    -1,    -1,    21,    22,    23,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,     3,     4,     5,
       6,    -1,    -1,    -1,    -1,    -1,    -1,    13,    -1,    15,
      -1,    -1,    -1,    -1,    -1,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,     3,     4,     5,    -1,     7,
      -1,    -1,    -1,    -1,    -1,    13,    -1,    15,    -1,    -1,
      -1,    -1,    -1,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,     3,     4,     5,    -1,    -1,     8,    -1,
      -1,    -1,    -1,    13,    -1,    15,    -1,    -1,    -1,    -1,
      -1,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,     4,     5,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      13,    -1,    15,    -1,    -1,    -1,    -1,    -1,    -1,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    -1,    40
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      13,    15,    21,    23,    26,    27,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,    42,    43,    44,
      45,    50,    52,    54,    55,    56,    63,     1,    24,    53,
       1,     3,     4,     5,     6,     7,     8,    13,    21,    22,
      23,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    56,    57,    60,
      62,     0,    22,    12,    45,    50,    43,    24,    28,    29,
      30,    21,    26,    27,    33,    34,    35,    46,    47,    43,
      21,     1,     3,     6,     7,     8,    21,    36,    56,    58,
      59,    61,    62,     1,     6,     7,     8,    39,    59,    21,
      23,    44,    24,    24,    24,     5,    51,    26,    27,    48,
      49,    34,    35,    43,    43,    21,    25,    47,    25,     3,
      56,    21,     1,     6,     7,     8,    39,    59,    21,     6,
      39,    59,     7,    39,    59,     8,    39,    59,    56,    61,
      24,     5,    31,    32,    25,    49,    43,    43,    25,    25,
      48,     3,    56,     6,    39,    59,     7,    39,    59,     8,
      39,    59,    56,    61,    24,    31,    51,    25,    25,    25,
      24,    31,    24
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    41,    42,    43,    43,    43,    44,    44,    44,    44,
      45,    45,    45,    46,    46,    47,    47,    48,    48,    49,
      49,    50,    50,    50,    50,    50,    50,    50,    50,    50,
      50,    50,    50,    50,    51,    51,    53,    52,    52,    52,
      52,    52,    52,    52,    52,    52,    52,    52,    52,    52,
      54,    54,    54,    54,    54,    54,    54,    55,    55,    55,
      55,    55,    55,    55,    55,    55,    55,    55,    55,    56,
      56,    56,    56,    56,    56,    56,    56,    56,    56,    56,
      56,    56,    56,    56,    56,    56,    56,    56,    56,    56,
      56,    56,    56,    56,    57,    57,    57,    57,    57,    57,
      57,    57,    57,    57,    57,    58,    58,    58,    58,    58,
      59,    59,    59,    59,    59,    59,    59,    59,    60,    60,
      60,    61,    61,    62,    62,    62,    62,    62,    62,    62,
      62,    62,    62,    62,    62,    62,    62,    62,    62,    62,
      62,    62,    63
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     1,     1,     3,     2,     1,     2,     2,     2,
       4,     5,     6,     1,     2,     1,     1,     1,     2,     1,
       1,     1,     3,     3,     3,     5,     6,     7,     2,     2,
       2,     4,     5,     6,     1,     2,     0,     4,     2,     6,
       6,     5,     5,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     3,
       4,     3,     2,     4,     3,     2,     4,     4,     2,     4,
       4,     2,     4,     4,     3,     5,     5,     3,     5,     5,
       3,     5,     5,     1,     2,     3,     3,     3,     3,     3,
       3,     3,     1,     1,     1,     2,     3,     3,     3,     1,
       3,     3,     3,     3,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (&yylloc, ctx, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF

/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
    do                                                                  \
      if (N)                                                            \
        {                                                               \
          (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;        \
          (Current).first_column = YYRHSLOC (Rhs, 1).first_column;      \
          (Current).last_line    = YYRHSLOC (Rhs, N).last_line;         \
          (Current).last_column  = YYRHSLOC (Rhs, N).last_column;       \
        }                                                               \
      else                                                              \
        {                                                               \
          (Current).first_line   = (Current).last_line   =              \
            YYRHSLOC (Rhs, 0).last_line;                                \
          (Current).first_column = (Current).last_column =              \
            YYRHSLOC (Rhs, 0).last_column;                              \
        }                                                               \
    while (0)
#endif

#define YYRHSLOC(Rhs, K) ((Rhs)[K])


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)


/* YYLOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

# ifndef YYLOCATION_PRINT

#  if defined YY_LOCATION_PRINT

   /* Temporary convenience wrapper in case some people defined the
      undocumented and private YY_LOCATION_PRINT macros.  */
#   define YYLOCATION_PRINT(File, Loc)  YY_LOCATION_PRINT(File, *(Loc))

#  elif defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL

/* Print *YYLOCP on YYO.  Private, do not rely on its existence. */

YY_ATTRIBUTE_UNUSED
static int
yy_location_print_ (FILE *yyo, YYLTYPE const * const yylocp)
{
  int res = 0;
  int end_col = 0 != yylocp->last_column ? yylocp->last_column - 1 : 0;
  if (0 <= yylocp->first_line)
    {
      res += YYFPRINTF (yyo, "%d", yylocp->first_line);
      if (0 <= yylocp->first_column)
        res += YYFPRINTF (yyo, ".%d", yylocp->first_column);
    }
  if (0 <= yylocp->last_line)
    {
      if (yylocp->first_line < yylocp->last_line)
        {
          res += YYFPRINTF (yyo, "-%d", yylocp->last_line);
          if (0 <= end_col)
            res += YYFPRINTF (yyo, ".%d", end_col);
        }
      else if (0 <= end_col && yylocp->first_column < end_col)
        res += YYFPRINTF (yyo, "-%d", end_col);
    }
  return res;
}

#   define YYLOCATION_PRINT  yy_location_print_

    /* Temporary convenience wrapper in case some people defined the
       undocumented and private YY_LOCATION_PRINT macros.  */
#   define YY_LOCATION_PRINT(File, Loc)  YYLOCATION_PRINT(File, &(Loc))

#  else

#   define YYLOCATION_PRINT(File, Loc) ((void) 0)
    /* Temporary convenience wrapper in case some people defined the
       undocumented and private YY_LOCATION_PRINT macros.  */
#   define YY_LOCATION_PRINT  YYLOCATION_PRINT

#  endif
# endif /* !defined YYLOCATION_PRINT */


# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value, Location, ctx); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, Context* ctx)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (yylocationp);
  YY_USE (ctx);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, Context* ctx)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  YYLOCATION_PRINT (yyo, yylocationp);
  YYFPRINTF (yyo, ": ");
  yy_symbol_value_print (yyo, yykind, yyvaluep, yylocationp, ctx);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, YYLTYPE *yylsp,
                 int yyrule, Context* ctx)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)],
                       &(yylsp[(yyi + 1) - (yynrhs)]), ctx);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, yylsp, Rule, ctx); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


/* Context of a parse error.  */
typedef struct
{
  yy_state_t *yyssp;
  yysymbol_kind_t yytoken;
  YYLTYPE *yylloc;
} yypcontext_t;

/* Put in YYARG at most YYARGN of the expected tokens given the
   current YYCTX, and return the number of tokens stored in YYARG.  If
   YYARG is null, return the number of expected tokens (guaranteed to
   be less than YYNTOKENS).  Return YYENOMEM on memory exhaustion.
   Return 0 if there are more than YYARGN expected tokens, yet fill
   YYARG up to YYARGN. */
static int
yypcontext_expected_tokens (const yypcontext_t *yyctx,
                            yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  int yyn = yypact[+*yyctx->yyssp];
  if (!yypact_value_is_default (yyn))
    {
      /* Start YYX at -YYN if negative to avoid negative indexes in
         YYCHECK.  In other words, skip the first -YYN actions for
         this state because they are default actions.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;
      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yyx;
      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
        if (yycheck[yyx + yyn] == yyx && yyx != YYSYMBOL_YYerror
            && !yytable_value_is_error (yytable[yyx + yyn]))
          {
            if (!yyarg)
              ++yycount;
            else if (yycount == yyargn)
              return 0;
            else
              yyarg[yycount++] = YY_CAST (yysymbol_kind_t, yyx);
          }
    }
  if (yyarg && yycount == 0 && 0 < yyargn)
    yyarg[0] = YYSYMBOL_YYEMPTY;
  return yycount;
}




#ifndef yystrlen
# if defined __GLIBC__ && defined _STRING_H
#  define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
# else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
# endif
#endif

#ifndef yystpcpy
# if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#  define yystpcpy stpcpy
# else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
# endif
#endif

#ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;
      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
#endif


static int
yy_syntax_error_arguments (const yypcontext_t *yyctx,
                           yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yyctx->yytoken != YYSYMBOL_YYEMPTY)
    {
      int yyn;
      if (yyarg)
        yyarg[yycount] = yyctx->yytoken;
      ++yycount;
      yyn = yypcontext_expected_tokens (yyctx,
                                        yyarg ? yyarg + 1 : yyarg, yyargn - 1);
      if (yyn == YYENOMEM)
        return YYENOMEM;
      else
        yycount += yyn;
    }
  return yycount;
}

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return -1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return YYENOMEM if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                const yypcontext_t *yyctx)
{
  enum { YYARGS_MAX = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  yysymbol_kind_t yyarg[YYARGS_MAX];
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* Actual size of YYARG. */
  int yycount = yy_syntax_error_arguments (yyctx, yyarg, YYARGS_MAX);
  if (yycount == YYENOMEM)
    return YYENOMEM;

  switch (yycount)
    {
#define YYCASE_(N, S)                       \
      case N:                               \
        yyformat = S;                       \
        break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
    }

  /* Compute error message size.  Don't count the "%s"s, but reserve
     room for the terminator.  */
  yysize = yystrlen (yyformat) - 2 * yycount + 1;
  {
    int yyi;
    for (yyi = 0; yyi < yycount; ++yyi)
      {
        YYPTRDIFF_T yysize1
          = yysize + yytnamerr (YY_NULLPTR, yytname[yyarg[yyi]]);
        if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
          yysize = yysize1;
        else
          return YYENOMEM;
      }
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return -1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yytname[yyarg[yyi++]]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, YYLTYPE *yylocationp, Context* ctx)
{
  YY_USE (yyvaluep);
  YY_USE (yylocationp);
  YY_USE (ctx);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}






/*----------.
| yyparse.  |
`----------*/

int
yyparse (Context* ctx)
{
/* Lookahead token kind.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

/* Location data for the lookahead symbol.  */
static YYLTYPE yyloc_default
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
  = { 1, 1, 1, 1 }
# endif
;
YYLTYPE yylloc = yyloc_default;

    /* Number of syntax errors so far.  */
    int yynerrs = 0;

    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

    /* The location stack: array, bottom, top.  */
    YYLTYPE yylsa[YYINITDEPTH];
    YYLTYPE *yyls = yylsa;
    YYLTYPE *yylsp = yyls;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

  /* The locations where the error started and ended.  */
  YYLTYPE yyerror_range[3];

  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  yylsp[0] = yylloc;
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;
        YYLTYPE *yyls1 = yyls;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yyls1, yysize * YYSIZEOF (*yylsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
        yyls = yyls1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
        YYSTACK_RELOCATE (yyls_alloc, yyls);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex (&yylval, &yylloc, ctx);
    }

  if (yychar <= END)
    {
      yychar = END;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      yyerror_range[1] = yylloc;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END
  *++yylsp = yylloc;

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

  /* Default location. */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  yyerror_range[1] = yyloc;
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2: /* regexp: alt  */
#line 140 "re_grammar.ypp"
  {
    ctx->Tree->Root = (yyval.node) = ctx->add(ParseNode::REGEXP, (yyvsp[0].node));
  }
#line 1914 "re_grammar.tab.cpp"
    break;

  case 4: /* alt: alt '|' concat  */
#line 148 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::ALTERNATION, (yyvsp[-2].node), (yyvsp[0].node));
  }
#line 1922 "re_grammar.tab.cpp"
    break;

  case 5: /* alt: switch alt  */
#line 152 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[0].node);
  }
#line 1930 "re_grammar.tab.cpp"
    break;

  case 7: /* concat: concat rep  */
#line 160 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::CONCATENATION, (yyvsp[-1].node), (yyvsp[0].node));
  }
#line 1938 "re_grammar.tab.cpp"
    break;

  case 8: /* concat: concat KILL  */
#line 164 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::LOOKBEHIND_POS, (yyvsp[-1].node));
  }
#line 1946 "re_grammar.tab.cpp"
    break;

  case 9: /* concat: concat switch  */
#line 168 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-1].node);
  }
#line 1954 "re_grammar.tab.cpp"
    break;

  case 15: /* switch_on: 'a'  */
#line 186 "re_grammar.ypp"
  {
    ctx->Opts.top() |= ASCII_MASK;
  }
#line 1962 "re_grammar.tab.cpp"
    break;

  case 16: /* switch_on: 'i'  */
#line 190 "re_grammar.ypp"
  {
    ctx->Opts.top() &= ~CASED_MASK;
  }
#line 1970 "re_grammar.tab.cpp"
    break;

  case 19: /* switch_off: 'a'  */
#line 202 "re_grammar.ypp"
  {
    ctx->Opts.top() &= ~ASCII_MASK;
  }
#line 1978 "re_grammar.tab.cpp"
    break;

  case 20: /* switch_off: 'i'  */
#line 206 "re_grammar.ypp"
  {
    ctx->Opts.top() |= CASED_MASK;
  }
#line 1986 "re_grammar.tab.cpp"
    break;

  case 22: /* rep: atom '*' '?'  */
#line 214 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION_NG, (yyvsp[-2].node), 0, UNBOUNDED);
  }
#line 1994 "re_grammar.tab.cpp"
    break;

  case 23: /* rep: atom '+' '?'  */
#line 218 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION_NG, (yyvsp[-2].node), 1, UNBOUNDED);
  }
#line 2002 "re_grammar.tab.cpp"
    break;

  case 24: /* rep: atom '?' '?'  */
#line 222 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION_NG, (yyvsp[-2].node), 0, 1);
  }
#line 2010 "re_grammar.tab.cpp"
    break;

  case 25: /* rep: atom '{' number '}' '?'  */
#line 226 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION_NG, (yyvsp[-4].node), (yyvsp[-2].node)->Val, (yyvsp[-2].node)->Val);
  }
#line 2018 "re_grammar.tab.cpp"
    break;

  case 26: /* rep: atom '{' number ',' '}' '?'  */
#line 230 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION_NG, (yyvsp[-5].node), (yyvsp[-3].node)->Val, UNBOUNDED);
  }
#line 2026 "re_grammar.tab.cpp"
    break;

  case 27: /* rep: atom '{' number ',' number '}' '?'  */
#line 234 "re_grammar.ypp"
  {
    if ((yyvsp[-4].node)->Val > (yyvsp[-2].node)->Val) {
      // {n,m} is ill-formed when n > m
      throwError(
        {
          ParseError::REVERSED_REPETITION_BOUNDS,
          (yylsp[-5]).first_column, (yylsp[0]).last_column,
          (yyvsp[-4].node)->Val, (yyvsp[-2].node)->Val
        },
        ctx
      );
    }
    else {
      (yyval.node) = ctx->add(ParseNode::REPETITION_NG, (yyvsp[-6].node), (yyvsp[-4].node)->Val, (yyvsp[-2].node)->Val);
    }
  }
#line 2047 "re_grammar.tab.cpp"
    break;

  case 28: /* rep: atom '*'  */
#line 251 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION, (yyvsp[-1].node), 0, UNBOUNDED);
  }
#line 2055 "re_grammar.tab.cpp"
    break;

  case 29: /* rep: atom '+'  */
#line 255 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION, (yyvsp[-1].node), 1, UNBOUNDED);
  }
#line 2063 "re_grammar.tab.cpp"
    break;

  case 30: /* rep: atom '?'  */
#line 259 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION, (yyvsp[-1].node), 0, 1);
  }
#line 2071 "re_grammar.tab.cpp"
    break;

  case 31: /* rep: atom '{' number '}'  */
#line 263 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION, (yyvsp[-3].node), (yyvsp[-1].node)->Val, (yyvsp[-1].node)->Val);
  }
#line 2079 "re_grammar.tab.cpp"
    break;

  case 32: /* rep: atom '{' number ',' '}'  */
#line 267 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::REPETITION, (yyvsp[-4].node), (yyvsp[-2].node)->Val, UNBOUNDED);
  }
#line 2087 "re_grammar.tab.cpp"
    break;

  case 33: /* rep: atom '{' number ',' number '}'  */
#line 271 "re_grammar.ypp"
  {
    if ((yyvsp[-3].node)->Val > (yyvsp[-1].node)->Val) {
      // {n,m} is ill-formed when n > m
      throwError(
        {
          ParseError::REVERSED_REPETITION_BOUNDS,
          (yylsp[-4]).first_column, (yylsp[0]).last_column,
          (yyvsp[-3].node)->Val, (yyvsp[-1].node)->Val,
        },
        ctx
      );
    }
    else {
      (yyval.node) = ctx->add(ParseNode::REPETITION, (yyvsp[-5].node), (yyvsp[-3].node)->Val, (yyvsp[-1].node)->Val);
    }
  }
#line 2108 "re_grammar.tab.cpp"
    break;

  case 34: /* number: DIGIT  */
#line 291 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::TEMPORARY, (yyvsp[0].c) - 48);
  }
#line 2116 "re_grammar.tab.cpp"
    break;

  case 35: /* number: number DIGIT  */
#line 295 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-1].node);
    (yyval.node)->Val = (yyval.node)->Val*10 + ((yyvsp[0].c) - 48);
  }
#line 2125 "re_grammar.tab.cpp"
    break;

  case 36: /* $@1: %empty  */
#line 302 "re_grammar.ypp"
      { ctx->Opts.push(ctx->Opts.top()); }
#line 2131 "re_grammar.tab.cpp"
    break;

  case 37: /* atom: '(' $@1 alt ')'  */
#line 303 "re_grammar.ypp"
  {
    ctx->Opts.pop();
    (yyval.node) = (yyvsp[-1].node);
  }
#line 2140 "re_grammar.tab.cpp"
    break;

  case 38: /* atom: '(' error  */
#line 308 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::UNMATCHED_PARENTHESIS,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2154 "re_grammar.tab.cpp"
    break;

  case 39: /* atom: '(' '?' '<' '=' alt ')'  */
#line 318 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::LOOKBEHIND_POS, (yyvsp[-1].node));
  }
#line 2162 "re_grammar.tab.cpp"
    break;

  case 40: /* atom: '(' '?' '<' '!' alt ')'  */
#line 322 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::LOOKBEHIND_NEG, (yyvsp[-1].node));
  }
#line 2170 "re_grammar.tab.cpp"
    break;

  case 41: /* atom: '(' '?' '=' alt ')'  */
#line 326 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::LOOKAHEAD_POS, (yyvsp[-1].node));
  }
#line 2178 "re_grammar.tab.cpp"
    break;

  case 42: /* atom: '(' '?' '!' alt ')'  */
#line 330 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::LOOKAHEAD_NEG, (yyvsp[-1].node));
  }
#line 2186 "re_grammar.tab.cpp"
    break;

  case 43: /* atom: WHACK_SMALL_B  */
#line 334 "re_grammar.ypp"
  {
    // TODO: ASCII mode affects \b as it's defined on \w, \W
    // \b  = ((?<!\w)(?!\W)|(?<!\W)(?!\w))

    ctx->USet.reset();
    ctx->USet.insert('0', '9' + 1);
    ctx->USet.insert('A', 'Z' + 1);
    ctx->USet.set('_');
    ctx->USet.insert('a', 'z' + 1);
    ParseNode* w = ctx->add(ParseNode::CHAR_CLASS, ctx->USet);

    ctx->USet.flip();
    ParseNode* W = ctx->add(ParseNode::CHAR_CLASS, ctx->USet);

    ParseNode* nlw = ctx->add(ParseNode::LOOKBEHIND_NEG, w);
    ParseNode* nrW = ctx->add(ParseNode::LOOKAHEAD_NEG, W);
    ParseNode* l = ctx->add(ParseNode::CONCATENATION, nlw, nrW);

    W = ctx->add(*W);
    w = ctx->add(*w);
    ParseNode* nlW = ctx->add(ParseNode::LOOKBEHIND_NEG, W);
    ParseNode* nrw = ctx->add(ParseNode::LOOKAHEAD_NEG, w);
    ParseNode* r = ctx->add(ParseNode::CONCATENATION, nlW, nrw);

    (yyval.node) = ctx->add(ParseNode::ALTERNATION, l, r);
  }
#line 2217 "re_grammar.tab.cpp"
    break;

  case 44: /* atom: NON_WORD_BOUNDARY  */
#line 361 "re_grammar.ypp"
  {
    // TODO: ASCII mode affects \B as it's defined on \w, \W
    // \B  = ((?<!\w)(?!\w)|(?<!\W)(?!\W))

    ctx->USet.reset();
    ctx->USet.insert('0', '9' + 1);
    ctx->USet.insert('A', 'Z' + 1);
    ctx->USet.set('_');
    ctx->USet.insert('a', 'z' + 1);
    ParseNode* w = ctx->add(ParseNode::CHAR_CLASS, ctx->USet);

    ctx->USet.flip();
    ParseNode* W = ctx->add(ParseNode::CHAR_CLASS, ctx->USet);

    ParseNode* nlw = ctx->add(ParseNode::LOOKBEHIND_NEG, w);
    w = ctx->add(*w);
    ParseNode* nrw = ctx->add(ParseNode::LOOKAHEAD_NEG, w);
    ParseNode* l = ctx->add(ParseNode::CONCATENATION, nlw, nrw);

    ParseNode* nlW = ctx->add(ParseNode::LOOKBEHIND_NEG, W);
    W = ctx->add(*W);
    ParseNode* nrW = ctx->add(ParseNode::LOOKAHEAD_NEG, W);
    ParseNode* r = ctx->add(ParseNode::CONCATENATION, nlW, nrW);

    (yyval.node) = ctx->add(ParseNode::ALTERNATION, l, r);
  }
#line 2248 "re_grammar.tab.cpp"
    break;

  case 45: /* atom: TEXT_START  */
#line 388 "re_grammar.ypp"
  {
    ParseNode *dot = ctx->add(ParseNode::DOT, '.');
    (yyval.node) = ctx->add(ParseNode::LOOKBEHIND_NEG, dot);
  }
#line 2257 "re_grammar.tab.cpp"
    break;

  case 46: /* atom: TEXT_END  */
#line 393 "re_grammar.ypp"
  {
    ParseNode *dot = ctx->add(ParseNode::DOT, '.');
    (yyval.node) = ctx->add(ParseNode::LOOKAHEAD_NEG, dot);
  }
#line 2266 "re_grammar.tab.cpp"
    break;

  case 47: /* atom: '^'  */
#line 398 "re_grammar.ypp"
  {
    ctx->USet.reset();
    ctx->USet.insert('\n', '\r' + 1); // \n \v \f \r
    ctx->USet.set(0x85);              // NEL
    ctx->USet.set(0x2028);            // LINE SEPARATOR
    ctx->USet.set(0x2029);            // PARAGRAPH SEPARATOR

    ParseNode *linebreak = ctx->add(ParseNode::CHAR_CLASS, ctx->USet);
    (yyval.node) = ctx->add(ParseNode::LOOKBEHIND_NEG, linebreak);
  }
#line 2281 "re_grammar.tab.cpp"
    break;

  case 48: /* atom: '$'  */
#line 409 "re_grammar.ypp"
  {
    ctx->USet.reset();
    ctx->USet.insert('\n', '\r' + 1); // \n \v \f \r
    ctx->USet.set(0x85);              // NEL
    ctx->USet.set(0x2028);            // LINE SEPARATOR
    ctx->USet.set(0x2029);            // PARAGRAPH SEPARATOR

    ParseNode *linebreak = ctx->add(ParseNode::CHAR_CLASS, ctx->USet);
    (yyval.node) = ctx->add(ParseNode::LOOKAHEAD_NEG, linebreak);
  }
#line 2296 "re_grammar.tab.cpp"
    break;

  case 50: /* literal: BYTE  */
#line 424 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::BYTE, (yyvsp[0].c));
  }
#line 2304 "re_grammar.tab.cpp"
    break;

  case 51: /* literal: character  */
#line 428 "re_grammar.ypp"
  {
    if (!(ctx->Opts.top() & CASED_MASK)) {
      ctx->USet.reset();
      ctx->USet.set((yyvsp[0].c));
      if (caseDesensitize(ctx->USet, ctx->Opts.top() & ASCII_MASK)) {
        // TODO: Maybe handle the commmon ASCII case without going via USet?
        (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, ctx->USet);
      }
      else {
        (yyval.node) = ctx->add(ParseNode::LITERAL, (yyvsp[0].c));
      }
    }
    else {
      (yyval.node) = ctx->add(ParseNode::LITERAL, (yyvsp[0].c));
    }
  }
#line 2325 "re_grammar.tab.cpp"
    break;

  case 52: /* literal: '.'  */
#line 445 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::DOT, '.');
  }
#line 2333 "re_grammar.tab.cpp"
    break;

  case 53: /* literal: HYPHEN_HYPHEN  */
#line 449 "re_grammar.ypp"
  {
    // This special case exists because -- is the set minus operator inside
    // character classes. Parsing -- together helps disambiguate set minus
    // from ranges. Here, outside of a char class, -- is just two hyphens.
    ParseNode* l = ctx->add(ParseNode::LITERAL, '-');
    ParseNode* r = ctx->add(ParseNode::LITERAL, '-');
    (yyval.node) = ctx->add(ParseNode::CONCATENATION, l, r);
  }
#line 2346 "re_grammar.tab.cpp"
    break;

  case 54: /* literal: AMP_AMP  */
#line 458 "re_grammar.ypp"
  {
    ParseNode* l = ctx->add(ParseNode::LITERAL, '&');
    ParseNode* r = ctx->add(ParseNode::LITERAL, '&');
    (yyval.node) = ctx->add(ParseNode::CONCATENATION, l, r);
  }
#line 2356 "re_grammar.tab.cpp"
    break;

  case 55: /* literal: TILDE_TILDE  */
#line 464 "re_grammar.ypp"
  {
    ParseNode* l = ctx->add(ParseNode::LITERAL, '~');
    ParseNode* r = ctx->add(ParseNode::LITERAL, '~');
    (yyval.node) = ctx->add(ParseNode::CONCATENATION, l, r);
  }
#line 2366 "re_grammar.tab.cpp"
    break;

  case 59: /* character: 'a'  */
#line 476 "re_grammar.ypp"
  {
    (yyval.c) = 'a';
  }
#line 2374 "re_grammar.tab.cpp"
    break;

  case 60: /* character: 'i'  */
#line 480 "re_grammar.ypp"
  {
    (yyval.c) = 'i';
  }
#line 2382 "re_grammar.tab.cpp"
    break;

  case 61: /* character: ']'  */
#line 484 "re_grammar.ypp"
  {
    (yyval.c) = ']';
  }
#line 2390 "re_grammar.tab.cpp"
    break;

  case 62: /* character: '-'  */
#line 488 "re_grammar.ypp"
  {
    (yyval.c) = '-';
  }
#line 2398 "re_grammar.tab.cpp"
    break;

  case 63: /* character: '{'  */
#line 492 "re_grammar.ypp"
  {
    (yyval.c) = '{';
  }
#line 2406 "re_grammar.tab.cpp"
    break;

  case 64: /* character: '}'  */
#line 496 "re_grammar.ypp"
  {
    (yyval.c) = '}';
  }
#line 2414 "re_grammar.tab.cpp"
    break;

  case 65: /* character: ','  */
#line 500 "re_grammar.ypp"
  {
    (yyval.c) = ',';
  }
#line 2422 "re_grammar.tab.cpp"
    break;

  case 66: /* character: '<'  */
#line 504 "re_grammar.ypp"
  {
    (yyval.c) = '<';
  }
#line 2430 "re_grammar.tab.cpp"
    break;

  case 67: /* character: '='  */
#line 508 "re_grammar.ypp"
  {
    (yyval.c) = '=';
  }
#line 2438 "re_grammar.tab.cpp"
    break;

  case 68: /* character: '!'  */
#line 512 "re_grammar.ypp"
  {
    (yyval.c) = '!';
  }
#line 2446 "re_grammar.tab.cpp"
    break;

  case 69: /* charclass: '[' cc_expr_pos ']'  */
#line 519 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-1].node);

    if (!(ctx->Opts.top() & CASED_MASK)) {
      caseDesensitize((yyval.node)->Set.CodePoints, ctx->Opts.top() & ASCII_MASK);
    }

    if ((yyval.node)->Set.CodePoints.none() && (yyval.node)->Set.Breakout.Bytes.none()) {
      // empty character class
      throwError(
        {
          ParseError::EMPTY_CHAR_CLASS,
          (yylsp[-2]).first_column, (yylsp[0]).last_column
        },
        ctx
      );
    }
  }
#line 2469 "re_grammar.tab.cpp"
    break;

  case 70: /* charclass: '[' '^' cc_expr_neg ']'  */
#line 538 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-1].node);

    if ((yyval.node)->Set.CodePoints.any()) {
      // NB: PCRE applies case-insensitivity first, then negation. This is
      // important, as these two operations do not commute on a cc such as
      // [^a]. Let U be the set of all Unicode code points. Negating first
      // gives U / {a}, which becomes U again when closing under case-
      // insensitivity, due to A being a member of U / {a}, while closing
      // under case-insensitivity first gives {A, a}, which becomes
      // U / {A, a} after negation.

      if (!(ctx->Opts.top() & CASED_MASK)) {
        caseDesensitize((yyval.node)->Set.CodePoints, ctx->Opts.top() & ASCII_MASK);
      }

      (yyval.node)->Set.CodePoints.flip();
      if ((yyval.node)->Set.CodePoints.none()) {
        // empty character class
        throwError(
          {
            ParseError::EMPTY_CHAR_CLASS,
            (yylsp[-3]).first_column, (yylsp[0]).last_column,
          },
          ctx
        );
      }

      if ((yyval.node)->Set.Breakout.Bytes.any()) {
        (yyval.node)->Set.Breakout.Additive = false;
      }
    }
    else if ((yyval.node)->Set.Breakout.Bytes.any()) {
      (yyval.node)->Set.Breakout.Bytes.flip();
      if ((yyval.node)->Set.Breakout.Bytes.none()) {
        // empty character class
        throwError(
          {
            ParseError::EMPTY_CHAR_CLASS,
            (yylsp[-3]).first_column, (yylsp[0]).last_column,
          },
          ctx
        );
      }
    }
    else {
      // empty inner character class
      (yyval.node)->Set.CodePoints.flip();
    }
  }
#line 2524 "re_grammar.tab.cpp"
    break;

  case 71: /* charclass: '[' cc_expr_pos error  */
#line 589 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::UNMATCHED_BRACKET,
        (yylsp[-2]).first_column, (yylsp[-2]).last_column
      },
      ctx
    );
  }
#line 2538 "re_grammar.tab.cpp"
    break;

  case 72: /* charclass: '[' error  */
#line 599 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::UNMATCHED_BRACKET,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2552 "re_grammar.tab.cpp"
    break;

  case 73: /* charclass: '[' '^' cc_expr_neg error  */
#line 609 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::UNMATCHED_BRACKET,
        (yylsp[-3]).first_column, (yylsp[-3]).last_column
      },
      ctx
    );
  }
#line 2566 "re_grammar.tab.cpp"
    break;

  case 74: /* charclass: '[' '^' error  */
#line 619 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::UNMATCHED_BRACKET,
        (yylsp[-2]).first_column, (yylsp[-2]).last_column
      },
      ctx
    );
  }
#line 2580 "re_grammar.tab.cpp"
    break;

  case 75: /* charclass: '[' AMP_AMP  */
#line 629 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[0]).first_column, (yylsp[0]).last_column
      },
      ctx
    );
  }
#line 2594 "re_grammar.tab.cpp"
    break;

  case 76: /* charclass: '[' cc_expr_pos AMP_AMP ']'  */
#line 639 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2608 "re_grammar.tab.cpp"
    break;

  case 77: /* charclass: '[' cc_expr_pos AMP_AMP AMP_AMP  */
#line 649 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2622 "re_grammar.tab.cpp"
    break;

  case 78: /* charclass: '[' HYPHEN_HYPHEN  */
#line 659 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[0]).first_column, (yylsp[0]).last_column
      },
      ctx
    );
  }
#line 2636 "re_grammar.tab.cpp"
    break;

  case 79: /* charclass: '[' cc_expr_pos HYPHEN_HYPHEN ']'  */
#line 669 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2650 "re_grammar.tab.cpp"
    break;

  case 80: /* charclass: '[' cc_expr_pos HYPHEN_HYPHEN HYPHEN_HYPHEN  */
#line 679 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2664 "re_grammar.tab.cpp"
    break;

  case 81: /* charclass: '[' TILDE_TILDE  */
#line 689 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[0]).first_column, (yylsp[0]).last_column
      },
      ctx
    );
  }
#line 2678 "re_grammar.tab.cpp"
    break;

  case 82: /* charclass: '[' cc_expr_pos TILDE_TILDE ']'  */
#line 699 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2692 "re_grammar.tab.cpp"
    break;

  case 83: /* charclass: '[' cc_expr_pos TILDE_TILDE TILDE_TILDE  */
#line 709 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2706 "re_grammar.tab.cpp"
    break;

  case 84: /* charclass: '[' '^' AMP_AMP  */
#line 719 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[0]).first_column, (yylsp[0]).last_column
      },
      ctx
    );
  }
#line 2720 "re_grammar.tab.cpp"
    break;

  case 85: /* charclass: '[' '^' cc_expr_neg AMP_AMP ']'  */
#line 729 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2734 "re_grammar.tab.cpp"
    break;

  case 86: /* charclass: '[' '^' cc_expr_neg AMP_AMP AMP_AMP  */
#line 739 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2748 "re_grammar.tab.cpp"
    break;

  case 87: /* charclass: '[' '^' HYPHEN_HYPHEN  */
#line 749 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[0]).first_column, (yylsp[0]).last_column
      },
      ctx
    );
  }
#line 2762 "re_grammar.tab.cpp"
    break;

  case 88: /* charclass: '[' '^' cc_expr_neg HYPHEN_HYPHEN ']'  */
#line 759 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2776 "re_grammar.tab.cpp"
    break;

  case 89: /* charclass: '[' '^' cc_expr_neg HYPHEN_HYPHEN HYPHEN_HYPHEN  */
#line 769 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2790 "re_grammar.tab.cpp"
    break;

  case 90: /* charclass: '[' '^' TILDE_TILDE  */
#line 779 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[0]).first_column, (yylsp[0]).last_column
      },
      ctx
    );
  }
#line 2804 "re_grammar.tab.cpp"
    break;

  case 91: /* charclass: '[' '^' cc_expr_neg TILDE_TILDE ']'  */
#line 789 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2818 "re_grammar.tab.cpp"
    break;

  case 92: /* charclass: '[' '^' cc_expr_neg TILDE_TILDE TILDE_TILDE  */
#line 799 "re_grammar.ypp"
  {
    throwError(
      {
        ParseError::SET_OPERATOR_MISSING_OPERAND,
        (yylsp[-1]).first_column, (yylsp[-1]).last_column
      },
      ctx
    );
  }
#line 2832 "re_grammar.tab.cpp"
    break;

  case 94: /* cc_expr_pos: cc_expr_pos cc_atom  */
#line 813 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-1].node);
    (yyval.node)->Set.CodePoints |= (yyvsp[0].node)->Set.CodePoints;
    (yyval.node)->Set.Breakout.Bytes |= (yyvsp[0].node)->Set.Breakout.Bytes;
  }
#line 2842 "re_grammar.tab.cpp"
    break;

  case 95: /* cc_expr_pos: cc_expr_pos AMP_AMP cc_atom  */
#line 819 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-2].node);
    (yyval.node)->Set.CodePoints &= (yyvsp[0].node)->Set.CodePoints;
    (yyval.node)->Set.Breakout.Bytes &= (yyvsp[0].node)->Set.Breakout.Bytes;
  }
#line 2852 "re_grammar.tab.cpp"
    break;

  case 96: /* cc_expr_pos: cc_expr_pos HYPHEN_HYPHEN cc_atom  */
#line 825 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-2].node);
    (yyval.node)->Set.CodePoints -= (yyvsp[0].node)->Set.CodePoints;
    (yyval.node)->Set.Breakout.Bytes -= (yyvsp[0].node)->Set.Breakout.Bytes;
  }
#line 2862 "re_grammar.tab.cpp"
    break;

  case 97: /* cc_expr_pos: cc_expr_pos TILDE_TILDE cc_atom  */
#line 831 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-2].node);
    (yyval.node)->Set.CodePoints ^= (yyvsp[0].node)->Set.CodePoints;
    (yyval.node)->Set.Breakout.Bytes ^= (yyvsp[0].node)->Set.Breakout.Bytes;
  }
#line 2872 "re_grammar.tab.cpp"
    break;

  case 98: /* cc_expr_pos: cc_char_first '-' cc_char_not_first  */
#line 837 "re_grammar.ypp"
  {
    if ((yyvsp[0].c) <= (yyvsp[-2].c)) {
      // x-y is ill-formed when y <= x
      throwError(
        {
          ParseError::REVERSED_CHAR_RANGE_BOUNDS,
          (yylsp[-2]).first_column, (yylsp[0]).last_column,
          (yyvsp[-2].c), (yyvsp[0].c)
        },
        ctx
      );
    }

    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, 'x');
    (yyval.node)->Set.CodePoints.insert((yyvsp[-2].c), (yyvsp[0].c) + 1);
  }
#line 2893 "re_grammar.tab.cpp"
    break;

  case 99: /* cc_expr_pos: cc_char_first '-' charclass  */
#line 854 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[0].node);
    (yyval.node)->Set.CodePoints.insert((yyvsp[-2].c), (yyvsp[-2].c) + 1);
    (yyval.node)->Set.CodePoints.insert('-', '-' + 1);
  }
#line 2903 "re_grammar.tab.cpp"
    break;

  case 100: /* cc_expr_pos: BYTE '-' BYTE  */
#line 860 "re_grammar.ypp"
  {
    if ((yyvsp[0].c) <= (yyvsp[-2].c)) {
      // x-y is ill-formed when y <= x
      throwError(
        {
          ParseError::REVERSED_BYTE_RANGE_BOUNDS,
          (yylsp[-2]).first_column, (yylsp[0]).last_column,
          (yyvsp[-2].c), (yyvsp[0].c)
        },
        ctx
      );
    }

    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, 'x');
    (yyval.node)->Set.Breakout.Bytes.set((yyvsp[-2].c), (yyvsp[0].c) + 1, true);
  }
#line 2924 "re_grammar.tab.cpp"
    break;

  case 101: /* cc_expr_pos: BYTE '-' charclass  */
#line 877 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[0].node);
    (yyval.node)->Set.Breakout.Bytes.set((yyvsp[-2].c));
    (yyval.node)->Set.CodePoints.insert('-', '-' + 1);
  }
#line 2934 "re_grammar.tab.cpp"
    break;

  case 103: /* cc_expr_pos: cc_char_first  */
#line 884 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, 'x');
    (yyval.node)->Set.CodePoints.set((yyvsp[0].c));
  }
#line 2943 "re_grammar.tab.cpp"
    break;

  case 104: /* cc_expr_pos: BYTE  */
#line 889 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, 'x');
    (yyval.node)->Set.Breakout.Bytes.set((yyvsp[0].c));
  }
#line 2952 "re_grammar.tab.cpp"
    break;

  case 105: /* cc_expr_neg: cc_expr_neg cc_atom  */
#line 897 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-1].node);
    (yyval.node)->Set.CodePoints |= (yyvsp[0].node)->Set.CodePoints;
    (yyval.node)->Set.Breakout.Bytes |= (yyvsp[0].node)->Set.Breakout.Bytes;
  }
#line 2962 "re_grammar.tab.cpp"
    break;

  case 106: /* cc_expr_neg: cc_expr_neg AMP_AMP cc_atom  */
#line 903 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-2].node);
    (yyval.node)->Set.CodePoints &= (yyvsp[0].node)->Set.CodePoints;
    (yyval.node)->Set.Breakout.Bytes &= (yyvsp[0].node)->Set.Breakout.Bytes;
  }
#line 2972 "re_grammar.tab.cpp"
    break;

  case 107: /* cc_expr_neg: cc_expr_neg HYPHEN_HYPHEN cc_atom  */
#line 909 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-2].node);
    (yyval.node)->Set.CodePoints -= (yyvsp[0].node)->Set.CodePoints;
    (yyval.node)->Set.Breakout.Bytes -= (yyvsp[0].node)->Set.Breakout.Bytes;
  }
#line 2982 "re_grammar.tab.cpp"
    break;

  case 108: /* cc_expr_neg: cc_expr_neg TILDE_TILDE cc_atom  */
#line 915 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[-2].node);
    (yyval.node)->Set.CodePoints ^= (yyvsp[0].node)->Set.CodePoints;
    (yyval.node)->Set.Breakout.Bytes ^= (yyvsp[0].node)->Set.Breakout.Bytes;
  }
#line 2992 "re_grammar.tab.cpp"
    break;

  case 110: /* cc_atom: cc_char_not_first '-' cc_char_not_first  */
#line 925 "re_grammar.ypp"
  {
    if ((yyvsp[0].c) <= (yyvsp[-2].c)) {
      // x-y is ill-formed when y <= x
      throwError(
        {
          ParseError::REVERSED_CHAR_RANGE_BOUNDS,
          (yylsp[-2]).first_column, (yylsp[0]).last_column,
          (yyvsp[-2].c), (yyvsp[0].c)
        },
        ctx
      );
    }

    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, 'x');
    (yyval.node)->Set.CodePoints.insert((yyvsp[-2].c), (yyvsp[0].c) + 1);
  }
#line 3013 "re_grammar.tab.cpp"
    break;

  case 111: /* cc_atom: cc_char_not_first '-' charclass  */
#line 942 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[0].node);
    (yyval.node)->Set.CodePoints.insert((yyvsp[-2].c), (yyvsp[-2].c) + 1);
    (yyval.node)->Set.CodePoints.insert('-', '-' + 1);
  }
#line 3023 "re_grammar.tab.cpp"
    break;

  case 112: /* cc_atom: BYTE '-' BYTE  */
#line 948 "re_grammar.ypp"
  {
    if ((yyvsp[0].c) <= (yyvsp[-2].c)) {
      // x-y is ill-formed when y <= x
      throwError(
        {
          ParseError::REVERSED_BYTE_RANGE_BOUNDS,
          (yylsp[-2]).first_column, (yylsp[0]).last_column,
          (yyvsp[-2].c), (yyvsp[0].c)
        },
        ctx
      );
    }

    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, 'x');
    (yyval.node)->Set.Breakout.Bytes.set((yyvsp[-2].c), (yyvsp[0].c) + 1, true);
  }
#line 3044 "re_grammar.tab.cpp"
    break;

  case 113: /* cc_atom: BYTE '-' charclass  */
#line 965 "re_grammar.ypp"
  {
    (yyval.node) = (yyvsp[0].node);
    (yyval.node)->Set.Breakout.Bytes.set((yyvsp[-2].c));
    (yyval.node)->Set.CodePoints.insert('-', '-' + 1);
  }
#line 3054 "re_grammar.tab.cpp"
    break;

  case 115: /* cc_atom: cc_char_not_first  */
#line 972 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, 'x');
    (yyval.node)->Set.CodePoints.set((yyvsp[0].c));
  }
#line 3063 "re_grammar.tab.cpp"
    break;

  case 116: /* cc_atom: '-'  */
#line 977 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, 'x');
    (yyval.node)->Set.CodePoints.set('-');
  }
#line 3072 "re_grammar.tab.cpp"
    break;

  case 117: /* cc_atom: BYTE  */
#line 982 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, 'x');
    (yyval.node)->Set.Breakout.Bytes.set((yyvsp[0].c));
  }
#line 3081 "re_grammar.tab.cpp"
    break;

  case 118: /* cc_char_first: ']'  */
#line 990 "re_grammar.ypp"
  {
    (yyval.c) = ']';
  }
#line 3089 "re_grammar.tab.cpp"
    break;

  case 119: /* cc_char_first: '-'  */
#line 994 "re_grammar.ypp"
  {
    (yyval.c) = '-';
  }
#line 3097 "re_grammar.tab.cpp"
    break;

  case 121: /* cc_char_not_first: '^'  */
#line 1002 "re_grammar.ypp"
  {
    (yyval.c) = '^';
  }
#line 3105 "re_grammar.tab.cpp"
    break;

  case 125: /* cc_char: 'a'  */
#line 1012 "re_grammar.ypp"
  {
    (yyval.c) = 'a';
  }
#line 3113 "re_grammar.tab.cpp"
    break;

  case 126: /* cc_char: 'i'  */
#line 1016 "re_grammar.ypp"
  {
    (yyval.c) = 'i';
  }
#line 3121 "re_grammar.tab.cpp"
    break;

  case 127: /* cc_char: '|'  */
#line 1020 "re_grammar.ypp"
  {
    (yyval.c) = '|';
  }
#line 3129 "re_grammar.tab.cpp"
    break;

  case 128: /* cc_char: '('  */
#line 1024 "re_grammar.ypp"
  {
    (yyval.c) = '(';
  }
#line 3137 "re_grammar.tab.cpp"
    break;

  case 129: /* cc_char: ')'  */
#line 1028 "re_grammar.ypp"
  {
    (yyval.c) = ')';
  }
#line 3145 "re_grammar.tab.cpp"
    break;

  case 130: /* cc_char: '?'  */
#line 1032 "re_grammar.ypp"
  {
    (yyval.c) = '?';
  }
#line 3153 "re_grammar.tab.cpp"
    break;

  case 131: /* cc_char: '+'  */
#line 1036 "re_grammar.ypp"
  {
    (yyval.c) = '+';
  }
#line 3161 "re_grammar.tab.cpp"
    break;

  case 132: /* cc_char: '*'  */
#line 1040 "re_grammar.ypp"
  {
    (yyval.c) = '*';
  }
#line 3169 "re_grammar.tab.cpp"
    break;

  case 133: /* cc_char: '.'  */
#line 1044 "re_grammar.ypp"
  {
    (yyval.c) = '.';
  }
#line 3177 "re_grammar.tab.cpp"
    break;

  case 134: /* cc_char: '{'  */
#line 1048 "re_grammar.ypp"
  {
    (yyval.c) = '{';
  }
#line 3185 "re_grammar.tab.cpp"
    break;

  case 135: /* cc_char: '}'  */
#line 1052 "re_grammar.ypp"
  {
    (yyval.c) = '}';
  }
#line 3193 "re_grammar.tab.cpp"
    break;

  case 136: /* cc_char: ','  */
#line 1056 "re_grammar.ypp"
  {
    (yyval.c) = ',';
  }
#line 3201 "re_grammar.tab.cpp"
    break;

  case 137: /* cc_char: '<'  */
#line 1060 "re_grammar.ypp"
  {
    (yyval.c) = '<';
  }
#line 3209 "re_grammar.tab.cpp"
    break;

  case 138: /* cc_char: '='  */
#line 1064 "re_grammar.ypp"
  {
    (yyval.c) = '=';
  }
#line 3217 "re_grammar.tab.cpp"
    break;

  case 139: /* cc_char: '!'  */
#line 1068 "re_grammar.ypp"
  {
    (yyval.c) = '!';
  }
#line 3225 "re_grammar.tab.cpp"
    break;

  case 140: /* cc_char: '$'  */
#line 1072 "re_grammar.ypp"
  {
    (yyval.c) = '$';
  }
#line 3233 "re_grammar.tab.cpp"
    break;

  case 141: /* cc_char: WHACK_SMALL_B  */
#line 1076 "re_grammar.ypp"
  {
    (yyval.c) = '\b';
  }
#line 3241 "re_grammar.tab.cpp"
    break;

  case 142: /* cc_named: SET  */
#line 1083 "re_grammar.ypp"
  {
    (yyval.node) = ctx->add(ParseNode::CHAR_CLASS, ctx->USet);
  }
#line 3249 "re_grammar.tab.cpp"
    break;


#line 3253 "re_grammar.tab.cpp"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      {
        yypcontext_t yyctx
          = {yyssp, yytoken, &yylloc};
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == -1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *,
                             YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (yymsg)
              {
                yysyntax_error_status
                  = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
                yymsgp = yymsg;
              }
            else
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = YYENOMEM;
              }
          }
        yyerror (&yylloc, ctx, yymsgp);
        if (yysyntax_error_status == YYENOMEM)
          YYNOMEM;
      }
    }

  yyerror_range[1] = yylloc;
  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= END)
        {
          /* Return failure if at end of input.  */
          if (yychar == END)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, &yylloc, ctx);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;

      yyerror_range[1] = *yylsp;
      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, yylsp, ctx);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  yyerror_range[2] = yylloc;
  ++yylsp;
  YYLLOC_DEFAULT (*yylsp, yyerror_range, 2);

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (&yylloc, ctx, YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, &yylloc, ctx);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, yylsp, ctx);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
  return yyresult;
}

#line 1088 "re_grammar.ypp"


namespace {

  template <typename F>
  int consumeSingleton(F func, yytokentype type, YYSTYPE* yylval, Context* ctx) {
    const int val = func(ctx->Text, ctx->TextEnd);
    if (val < 0) {
      return BAD;
    }
    else {
      yylval->c = val;
      return type;
    }
  }

  template <typename F>
  int consumeSet(F func, YYSTYPE* yylval, Context* ctx) {
    const int val = func(
      ctx->Text, ctx->TextEnd, ctx->USet, !(ctx->Opts.top() & CASED_MASK)
    );
    if (val < 0) {
      return BAD;
    }
    else {
      yylval->s = &ctx->USet;
      return SET;
    }
  }

// FIXME: Add \c.

  int consumeEscape(YYSTYPE* yylval, Context* ctx) {
    if (ctx->Text >= ctx->TextEnd) {
      return BAD;
    }

    const int c = *ctx->Text++;
    switch (c) {
    // metacharacters as themselves
    case '|':
    case '(':
    case ')':
    case '?':
    case '+':
    case '*':
    case '.':
    case '[':
    case ']':
    case '^':
    case '$':
    case '-':
    case '{':
    case '}':
    case '&':
    case '~':
    case '<':
    case '=':
    case '!':
    case '\\':
      yylval->c = c;
      return CHAR;

    // ASCII escapes
    case 'a':
      yylval->c = '\a';
      return CHAR;
    case 'e':
      yylval->c = 0x1B;
      return CHAR;
    case 'f':
      yylval->c = '\f';
      return CHAR;
    case 'n':
      yylval->c = '\n';
      return CHAR;
    case 'r':
      yylval->c = '\r';
      return CHAR;
    case 't':
      yylval->c = '\t';
      return CHAR;

    // named character classes
    case 'd':
      ctx->USet.reset();
      setDigitClass(ctx->USet, ctx->Opts.top() & ASCII_MASK);
      yylval->s = &ctx->USet;
      return SET;

    case 'D':
      ctx->USet.reset();
      setDigitClass(ctx->USet, ctx->Opts.top() & ASCII_MASK);
      ctx->USet.flip();
      yylval->s = &ctx->USet;
      return SET;

    case 's':
      ctx->USet.reset();
      setSpaceClass(ctx->USet, ctx->Opts.top() & ASCII_MASK);
      yylval->s = &ctx->USet;
      return SET;

    case 'S':
      ctx->USet.reset();
      setSpaceClass(ctx->USet, ctx->Opts.top() & ASCII_MASK);
      ctx->USet.flip();
      yylval->s = &ctx->USet;
      return SET;

    case 'h':
      ctx->USet.reset();
      setHorizontalSpaceClass(ctx->USet);
      yylval->s = &ctx->USet;
      return SET;

    case 'H':
      ctx->USet.reset();
      setHorizontalSpaceClass(ctx->USet);
      ctx->USet.flip();
      yylval->s = &ctx->USet;
      return SET;

    case 'v':
      ctx->USet.reset();
      setVerticalSpaceClass(ctx->USet);
      yylval->s = &ctx->USet;
      return SET;

    case 'V':
      ctx->USet.reset();
      setVerticalSpaceClass(ctx->USet);
      ctx->USet.flip();
      yylval->s = &ctx->USet;
      return SET;

    case 'w':
      ctx->USet.reset();
      setWordClass(ctx->USet, ctx->Opts.top() & ASCII_MASK);
      yylval->s = &ctx->USet;
      return SET;

    case 'W':
      ctx->USet.reset();
      setWordClass(ctx->USet, ctx->Opts.top() & ASCII_MASK);
      ctx->USet.flip();
      yylval->s = &ctx->USet;
      return SET;

    // hexadecimal characters
    case 'x':
      if (ctx->Text == ctx->TextEnd) {
        return BAD;
      }
      else if (*ctx->Text == '{') {
        ++ctx->Text;
        return consumeSingleton(parseHexCodePoint<const int*>, CHAR, yylval, ctx);
      }
      else {
        return consumeSingleton(parseHexByte<const int*>, CHAR, yylval, ctx);
      }

    // breakout bytes
    case 'z':
      return consumeSingleton(parseHexByte<const int*>, BYTE, yylval, ctx);

    // octal characters
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
      --ctx->Text;
      return consumeSingleton(parseOctByte<const int*>, CHAR, yylval, ctx);

    // named Unicode code points
    case 'N':
      return consumeSingleton(parseNamedCodePoint<const int*>, CHAR, yylval, ctx);

    // Unicode properties
    case 'p':
    case 'P':
      ctx->Text -= 2;
      return consumeSet(parseProperty<const int*>, yylval, ctx);

    // assertions
    case 'A':
      return TEXT_START;
    case 'B':
      return NON_WORD_BOUNDARY;
    case 'K':
      return KILL;
    case 'Z':
      return TEXT_END;
    case 'b':
      return WHACK_SMALL_B; // NB: Also an ASCII escape inside CCs

    default:
      return BAD;
    }
  }

  int yylex(YYSTYPE* yylval, YYLTYPE* yylloc, Context* ctx) {
    yylloc->first_column = ctx->Text - ctx->TextBegin;

    ctx->TokenType = -1;  // EOF

    if (ctx->Text < ctx->TextEnd) {
      const int c = *ctx->Text++;
      yylloc->last_column = yylloc->first_column + 1;
      if (c < 1) {
        //   -1 indicates bogus UTF-8
        //    0 is a prohibited mid-string null byte
        ctx->TokenType = BAD;
      }
      else if (ctx->LiteralMode) {
        yylval->c = c;
        ctx->TokenType = CHAR;
      }
      else {
        switch (c) {
        case 'a':
        case 'i':
        case '|':
        case '(':
        case ')':
        case '?':
        case '+':
        case '*':
        case '.':
        case '[':
        case ']':
        case '^':
        case '$':
        case '{':
        case '}':
        case ',':
        case '<':
        case '=':
        case '!':
          ctx->TokenType = c;
          break;
        case '&':
          if (ctx->Text < ctx->TextEnd && *ctx->Text == '&') {
              // give the parser a hint that this amp might be an intersection
              yylloc->last_column = ++ctx->Text - ctx->TextBegin;
              ctx->TokenType = AMP_AMP;
          }
          else {
            // give the parser a hint that this ampersand is a literal
            yylval->c = c;
            ctx->TokenType = CHAR;
          }
          break;
        case '~':
          if (ctx->Text < ctx->TextEnd && *ctx->Text == '~') {
            // give the parser a hint that this tilde might be an XOR
            yylloc->last_column = ++ctx->Text - ctx->TextBegin;
            ctx->TokenType = TILDE_TILDE;
          }
          else {
            // give the parser a hint that this tilde is a literal
            yylval->c = c;
            ctx->TokenType = CHAR;
          }
          break;
        case '-':
          if (ctx->Text < ctx->TextEnd) {
            switch (*ctx->Text) {
            case ']':
              // give the parser a hint that this hypen is a literal
              yylval->c = c;
              ctx->TokenType = CHAR;
              break;
            case '-':
              // give the parser a hint that this hypen might be a minus
              yylloc->last_column = ++ctx->Text - ctx->TextBegin;
              ctx->TokenType = HYPHEN_HYPHEN;
              break;
            default:
              // this hyphen might be a range operator if inside a cc
              ctx->TokenType = '-';
              break;
            }
          }
          else {
            yylval->c = c;
            ctx->TokenType = CHAR;
          }
          break;
        case '\\':
          ctx->TokenType = consumeEscape(yylval, ctx);
          yylloc->last_column = ctx->Text - ctx->TextBegin;
          break;
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
          yylval->c = c;
          ctx->TokenType = DIGIT;
          break;
        default:
          yylval->c = c;
          ctx->TokenType = CHAR;
          break;
        }
      }
    }

    return ctx->TokenType;
  }

  void yyerror(YYLTYPE* yylloc, Context* ctx, const char*) {
    /*
       NB: We do not call yyerror ourselves, in order to ensure that if
       control arrives here, it happened due to a syntax error detected
       by bison (as opposed to a semantic error we detect in one of the
       parse rules. This lets us deduce which error we have by examining
       the state of the parser.
    */

    if (ctx->TokenType == BAD) {
      // The token read was something invalid.
      ParseError e{
        ParseError::INVALID_ESCAPE,
        yylloc->first_column,
        yylloc->last_column
      };

      throwError(e, ctx);
    }
    else if (yylloc->first_column == yylloc->last_column) {
      // We ran off the end of the pattern looking for a matching delimiter.
      // We return rather than throw here to let the error recovery action
      // execute. The error recovery action knows the location of the
      // unmatched delimiter.
      return;
    }
    else {
      // The only remaining way to fail is a repetition operator
      // following a non-atom.
      ParseError e{
        ParseError::NONATOMIC_REPETITON,
        yylloc->first_column,
        yylloc->last_column
      };

      throwError(e, ctx);
    }
  }

  void throwError(ParseError e, Context* ctx) {
    std::ostringstream ss;

    switch (e.Type) {
    case ParseError::NONATOMIC_REPETITON:
      ss << "repetition of non-atom by ";
      break;
    case ParseError::REVERSED_REPETITION_BOUNDS:
      ss << e.First << " > " << e.Second << " in ";
      break;
    case ParseError::INVALID_ESCAPE:
      ss << "invalid escape ";
      break;
    case ParseError::UNMATCHED_PARENTHESIS:
      ss << "unmatched left parenthesis ";
      break;
    case ParseError::UNMATCHED_BRACKET:
      ss << "unmatched left bracket ";
      break;
    case ParseError::EMPTY_CHAR_CLASS:
      ss << "empty character class ";
      break;
    case ParseError::REVERSED_CHAR_RANGE_BOUNDS:
      ss << "U+" << std::hex << std::uppercase
         <<  e.First << " >= U+" << e.Second << std::dec << " in ";
      break;
    case ParseError::REVERSED_BYTE_RANGE_BOUNDS:
      ss << "0x" << std::hex << std::uppercase << std::setfill('0')
         << std::setw(2) << e.First << " >= 0x"
         << std::setw(2) << e.Second << std::dec << " in ";
      break;
    case ParseError::SET_OPERATOR_MISSING_OPERAND:
      ss << "missing operand for ";
      break;
    }

    std::copy(
      ctx->TextBegin + e.Begin,
      ctx->TextBegin + e.End,
      std::ostream_iterator<char>(ss)
    );

    ss << ", at [" << e.Begin << ',' << e.End << ')';

    THROW_RUNTIME_ERROR_WITH_CLEAN_OUTPUT(ss.str());
  }
}

bool parse(const Pattern& p, ParseTree& tree) {
  std::vector<int> cp;
  cp.reserve(p.Expression.size()); // upper bound, no resizing
  transform_utf8_to_unicode(
    p.Expression.begin(), p.Expression.end(), std::back_inserter(cp)
  );

  Context ctx;

  ctx.LiteralMode = p.FixedString;
  ctx.Opts.push(
    (p.CaseInsensitive ? 0 : CASED_MASK) |
    (p.UnicodeMode ? 0 : ASCII_MASK)
  );

  ctx.TextBegin = ctx.Text = cp.data();
  ctx.TextEnd = ctx.Text + cp.size();

  ctx.Tree = &tree;
  ctx.Tree->init(cp.size());

#if YYDEBUG
  yydebug = 1;
#endif

  return yyparse(&ctx) == 0;
}
