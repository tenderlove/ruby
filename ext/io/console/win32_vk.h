/* C code produced by gperf version 3.0.4 */
/* Command-line: gperf --ignore-case -E -C -P -p -j1 -i 1 -g -o -t -K ofs -N console_win32_vk -k'*' --output-file=win32_vk.h win32_vk.list  */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif

#line 1 "win32_vk.list"

struct vktable {short ofs; unsigned short vk;};
static const struct vktable *console_win32_vk(const char *, unsigned int);
#line 5 "win32_vk.list"
struct vktable;
/* maximum key range = 245, duplicates = 0 */

#ifndef GPERF_DOWNCASE
#define GPERF_DOWNCASE 1
static unsigned char gperf_downcase[256] =
  {
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
     30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
     45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
     60,  61,  62,  63,  64,  97,  98,  99, 100, 101, 102, 103, 104, 105, 106,
    107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122,  91,  92,  93,  94,  95,  96,  97,  98,  99, 100, 101, 102, 103, 104,
    105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
    135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
    165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
    195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
    210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    255
  };
#endif

#ifndef GPERF_CASE_STRCMP
#define GPERF_CASE_STRCMP 1
static int
gperf_case_strcmp (s1, s2)
     register const char *s1;
     register const char *s2;
{
  for (;;)
    {
      unsigned char c1 = gperf_downcase[(unsigned char)*s1++];
      unsigned char c2 = gperf_downcase[(unsigned char)*s2++];
      if (c1 != 0 && c1 == c2)
        continue;
      return (int)c1 - (int)c2;
    }
}
#endif

#if (defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || defined(__cplusplus) || defined(__GNUC_STDC_INLINE__)
inline
#elif defined(__GNUC__)
__inline
#endif
static unsigned int
hash (str, len)
     register const char *str;
     register unsigned int len;
{
  static const unsigned short asso_values[] =
    {
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257,  51,  74,
       80, 116, 127, 124,  95, 140,  77,  53,   7,   3,
      257, 257, 257, 257, 257,   1,  11,   1,  55,   1,
       25,  84,  31,  33,  13,  16,   2,  28,   8,   1,
        6,  10,   1,   1,   3,   4,  45,  18,  73,  79,
       30, 257, 257, 257, 257,   5, 257,   1,  11,   1,
       55,   1,  25,  84,  31,  33,  13,  16,   2,  28,
        8,   1,   6,  10,   1,   1,   3,   4,  45,  18,
       73,  79,  30, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257, 257, 257,
      257, 257, 257, 257, 257, 257, 257, 257
    };
  register int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[18]];
      /*FALLTHROUGH*/
      case 18:
        hval += asso_values[(unsigned char)str[17]];
      /*FALLTHROUGH*/
      case 17:
        hval += asso_values[(unsigned char)str[16]];
      /*FALLTHROUGH*/
      case 16:
        hval += asso_values[(unsigned char)str[15]];
      /*FALLTHROUGH*/
      case 15:
        hval += asso_values[(unsigned char)str[14]];
      /*FALLTHROUGH*/
      case 14:
        hval += asso_values[(unsigned char)str[13]];
      /*FALLTHROUGH*/
      case 13:
        hval += asso_values[(unsigned char)str[12]];
      /*FALLTHROUGH*/
      case 12:
        hval += asso_values[(unsigned char)str[11]];
      /*FALLTHROUGH*/
      case 11:
        hval += asso_values[(unsigned char)str[10]];
      /*FALLTHROUGH*/
      case 10:
        hval += asso_values[(unsigned char)str[9]];
      /*FALLTHROUGH*/
      case 9:
        hval += asso_values[(unsigned char)str[8]];
      /*FALLTHROUGH*/
      case 8:
        hval += asso_values[(unsigned char)str[7]];
      /*FALLTHROUGH*/
      case 7:
        hval += asso_values[(unsigned char)str[6]];
      /*FALLTHROUGH*/
      case 6:
        hval += asso_values[(unsigned char)str[5]];
      /*FALLTHROUGH*/
      case 5:
        hval += asso_values[(unsigned char)str[4]];
      /*FALLTHROUGH*/
      case 4:
        hval += asso_values[(unsigned char)str[3]];
      /*FALLTHROUGH*/
      case 3:
        hval += asso_values[(unsigned char)str[2]+2];
      /*FALLTHROUGH*/
      case 2:
        hval += asso_values[(unsigned char)str[1]];
      /*FALLTHROUGH*/
      case 1:
        hval += asso_values[(unsigned char)str[0]];
        break;
    }
  return hval;
}

struct stringpool_t
  {
    char stringpool_str12[sizeof("UP")];
    char stringpool_str13[sizeof("APPS")];
    char stringpool_str14[sizeof("CRSEL")];
    char stringpool_str15[sizeof("SPACE")];
    char stringpool_str16[sizeof("SCROLL")];
    char stringpool_str17[sizeof("ESCAPE")];
    char stringpool_str18[sizeof("CANCEL")];
    char stringpool_str19[sizeof("ACCEPT")];
    char stringpool_str20[sizeof("SEPARATOR")];
    char stringpool_str21[sizeof("SELECT")];
    char stringpool_str22[sizeof("CONTROL")];
    char stringpool_str23[sizeof("OEM_CLEAR")];
    char stringpool_str24[sizeof("OEM_RESET")];
    char stringpool_str25[sizeof("OEM_AUTO")];
    char stringpool_str26[sizeof("OEM_CUSEL")];
    char stringpool_str28[sizeof("KANA")];
    char stringpool_str29[sizeof("OEM_PLUS")];
    char stringpool_str30[sizeof("PRIOR")];
    char stringpool_str31[sizeof("OEM_ATTN")];
    char stringpool_str32[sizeof("PAUSE")];
    char stringpool_str33[sizeof("BACK")];
    char stringpool_str34[sizeof("PACKET")];
    char stringpool_str35[sizeof("RCONTROL")];
    char stringpool_str36[sizeof("LCONTROL")];
    char stringpool_str37[sizeof("END")];
    char stringpool_str38[sizeof("HOME")];
    char stringpool_str39[sizeof("PRINT")];
    char stringpool_str40[sizeof("NUMLOCK")];
    char stringpool_str41[sizeof("LEFT")];
    char stringpool_str42[sizeof("JUNJA")];
    char stringpool_str43[sizeof("MENU")];
    char stringpool_str44[sizeof("OEM_WSCTRL")];
    char stringpool_str45[sizeof("OEM_ENLW")];
    char stringpool_str46[sizeof("NEXT")];
    char stringpool_str47[sizeof("RWIN")];
    char stringpool_str48[sizeof("LWIN")];
    char stringpool_str49[sizeof("CAPITAL")];
    char stringpool_str50[sizeof("HELP")];
    char stringpool_str51[sizeof("NONAME")];
    char stringpool_str52[sizeof("RBUTTON")];
    char stringpool_str53[sizeof("LBUTTON")];
    char stringpool_str54[sizeof("OEM_NEC_EQUAL")];
    char stringpool_str56[sizeof("INSERT")];
    char stringpool_str57[sizeof("HANJA")];
    char stringpool_str60[sizeof("SNAPSHOT")];
    char stringpool_str61[sizeof("ATTN")];
    char stringpool_str62[sizeof("TAB")];
    char stringpool_str63[sizeof("OEM_BACKTAB")];
    char stringpool_str64[sizeof("ICO_CLEAR")];
    char stringpool_str65[sizeof("CONVERT")];
    char stringpool_str66[sizeof("RETURN")];
    char stringpool_str67[sizeof("OEM_JUMP")];
    char stringpool_str71[sizeof("BROWSER_STOP")];
    char stringpool_str72[sizeof("FINAL")];
    char stringpool_str73[sizeof("ZOOM")];
    char stringpool_str74[sizeof("KANJI")];
    char stringpool_str75[sizeof("DELETE")];
    char stringpool_str76[sizeof("OEM_COMMA")];
    char stringpool_str77[sizeof("SUBTRACT")];
    char stringpool_str79[sizeof("MBUTTON")];
    char stringpool_str80[sizeof("F9")];
    char stringpool_str81[sizeof("SHIFT")];
    char stringpool_str82[sizeof("RSHIFT")];
    char stringpool_str83[sizeof("LSHIFT")];
    char stringpool_str84[sizeof("ADD")];
    char stringpool_str85[sizeof("NONCONVERT")];
    char stringpool_str86[sizeof("EXSEL")];
    char stringpool_str87[sizeof("OEM_1")];
    char stringpool_str88[sizeof("OEM_AX")];
    char stringpool_str89[sizeof("BROWSER_BACK")];
    char stringpool_str90[sizeof("OEM_8")];
    char stringpool_str91[sizeof("OEM_MINUS")];
    char stringpool_str92[sizeof("PLAY")];
    char stringpool_str93[sizeof("OEM_2")];
    char stringpool_str94[sizeof("CLEAR")];
    char stringpool_str95[sizeof("OEM_FJ_TOUROKU")];
    char stringpool_str96[sizeof("OEM_PA1")];
    char stringpool_str97[sizeof("ICO_HELP")];
    char stringpool_str98[sizeof("BROWSER_SEARCH")];
    char stringpool_str99[sizeof("SLEEP")];
    char stringpool_str101[sizeof("F1")];
    char stringpool_str102[sizeof("OEM_PA2")];
    char stringpool_str103[sizeof("OEM_COPY")];
    char stringpool_str104[sizeof("F8")];
    char stringpool_str105[sizeof("F19")];
    char stringpool_str106[sizeof("RIGHT")];
    char stringpool_str107[sizeof("F2")];
    char stringpool_str108[sizeof("OEM_6")];
    char stringpool_str109[sizeof("F18")];
    char stringpool_str111[sizeof("VOLUME_UP")];
    char stringpool_str114[sizeof("MEDIA_STOP")];
    char stringpool_str115[sizeof("OEM_PERIOD")];
    char stringpool_str117[sizeof("EREOF")];
    char stringpool_str121[sizeof("BROWSER_HOME")];
    char stringpool_str122[sizeof("F6")];
    char stringpool_str124[sizeof("BROWSER_REFRESH")];
    char stringpool_str126[sizeof("PA1")];
    char stringpool_str127[sizeof("PROCESSKEY")];
    char stringpool_str128[sizeof("DECIMAL")];
    char stringpool_str129[sizeof("OEM_3")];
    char stringpool_str130[sizeof("RMENU")];
    char stringpool_str131[sizeof("LMENU")];
    char stringpool_str132[sizeof("OEM_FJ_MASSHOU")];
    char stringpool_str133[sizeof("NUMPAD0")];
    char stringpool_str134[sizeof("HANGUL")];
    char stringpool_str135[sizeof("NUMPAD9")];
    char stringpool_str136[sizeof("HANGEUL")];
    char stringpool_str137[sizeof("OEM_5")];
    char stringpool_str138[sizeof("OEM_PA3")];
    char stringpool_str139[sizeof("VOLUME_MUTE")];
    char stringpool_str140[sizeof("OEM_4")];
    char stringpool_str141[sizeof("LAUNCH_MAIL")];
    char stringpool_str142[sizeof("OEM_FJ_JISHO")];
    char stringpool_str143[sizeof("F3")];
    char stringpool_str144[sizeof("OEM_FJ_ROYA")];
    char stringpool_str145[sizeof("OEM_FJ_LOYA")];
    char stringpool_str147[sizeof("DOWN")];
    char stringpool_str149[sizeof("OEM_FINISH")];
    char stringpool_str151[sizeof("F5")];
    char stringpool_str153[sizeof("OEM_7")];
    char stringpool_str154[sizeof("F4")];
    char stringpool_str155[sizeof("F17")];
    char stringpool_str156[sizeof("NUMPAD1")];
    char stringpool_str157[sizeof("ICO_00")];
    char stringpool_str159[sizeof("NUMPAD8")];
    char stringpool_str162[sizeof("NUMPAD2")];
    char stringpool_str164[sizeof("LAUNCH_APP1")];
    char stringpool_str165[sizeof("BROWSER_FORWARD")];
    char stringpool_str167[sizeof("F7")];
    char stringpool_str170[sizeof("LAUNCH_APP2")];
    char stringpool_str171[sizeof("MULTIPLY")];
    char stringpool_str174[sizeof("EXECUTE")];
    char stringpool_str176[sizeof("BROWSER_FAVORITES")];
    char stringpool_str177[sizeof("NUMPAD6")];
    char stringpool_str179[sizeof("F16")];
    char stringpool_str182[sizeof("F10")];
    char stringpool_str185[sizeof("VOLUME_DOWN")];
    char stringpool_str188[sizeof("F20")];
    char stringpool_str189[sizeof("MEDIA_PREV_TRACK")];
    char stringpool_str191[sizeof("MODECHANGE")];
    char stringpool_str197[sizeof("F14")];
    char stringpool_str198[sizeof("NUMPAD3")];
    char stringpool_str199[sizeof("XBUTTON1")];
    char stringpool_str203[sizeof("F24")];
    char stringpool_str205[sizeof("XBUTTON2")];
    char stringpool_str206[sizeof("NUMPAD5")];
    char stringpool_str209[sizeof("NUMPAD4")];
    char stringpool_str215[sizeof("MEDIA_PLAY_PAUSE")];
    char stringpool_str217[sizeof("LAUNCH_MEDIA_SELECT")];
    char stringpool_str218[sizeof("F11")];
    char stringpool_str220[sizeof("OEM_102")];
    char stringpool_str221[sizeof("MEDIA_NEXT_TRACK")];
    char stringpool_str222[sizeof("NUMPAD7")];
    char stringpool_str224[sizeof("F21")];
    char stringpool_str226[sizeof("F13")];
    char stringpool_str229[sizeof("F12")];
    char stringpool_str232[sizeof("F23")];
    char stringpool_str235[sizeof("F22")];
    char stringpool_str242[sizeof("F15")];
    char stringpool_str256[sizeof("DIVIDE")];
  };
static const struct stringpool_t stringpool_contents =
  {
    "UP",
    "APPS",
    "CRSEL",
    "SPACE",
    "SCROLL",
    "ESCAPE",
    "CANCEL",
    "ACCEPT",
    "SEPARATOR",
    "SELECT",
    "CONTROL",
    "OEM_CLEAR",
    "OEM_RESET",
    "OEM_AUTO",
    "OEM_CUSEL",
    "KANA",
    "OEM_PLUS",
    "PRIOR",
    "OEM_ATTN",
    "PAUSE",
    "BACK",
    "PACKET",
    "RCONTROL",
    "LCONTROL",
    "END",
    "HOME",
    "PRINT",
    "NUMLOCK",
    "LEFT",
    "JUNJA",
    "MENU",
    "OEM_WSCTRL",
    "OEM_ENLW",
    "NEXT",
    "RWIN",
    "LWIN",
    "CAPITAL",
    "HELP",
    "NONAME",
    "RBUTTON",
    "LBUTTON",
    "OEM_NEC_EQUAL",
    "INSERT",
    "HANJA",
    "SNAPSHOT",
    "ATTN",
    "TAB",
    "OEM_BACKTAB",
    "ICO_CLEAR",
    "CONVERT",
    "RETURN",
    "OEM_JUMP",
    "BROWSER_STOP",
    "FINAL",
    "ZOOM",
    "KANJI",
    "DELETE",
    "OEM_COMMA",
    "SUBTRACT",
    "MBUTTON",
    "F9",
    "SHIFT",
    "RSHIFT",
    "LSHIFT",
    "ADD",
    "NONCONVERT",
    "EXSEL",
    "OEM_1",
    "OEM_AX",
    "BROWSER_BACK",
    "OEM_8",
    "OEM_MINUS",
    "PLAY",
    "OEM_2",
    "CLEAR",
    "OEM_FJ_TOUROKU",
    "OEM_PA1",
    "ICO_HELP",
    "BROWSER_SEARCH",
    "SLEEP",
    "F1",
    "OEM_PA2",
    "OEM_COPY",
    "F8",
    "F19",
    "RIGHT",
    "F2",
    "OEM_6",
    "F18",
    "VOLUME_UP",
    "MEDIA_STOP",
    "OEM_PERIOD",
    "EREOF",
    "BROWSER_HOME",
    "F6",
    "BROWSER_REFRESH",
    "PA1",
    "PROCESSKEY",
    "DECIMAL",
    "OEM_3",
    "RMENU",
    "LMENU",
    "OEM_FJ_MASSHOU",
    "NUMPAD0",
    "HANGUL",
    "NUMPAD9",
    "HANGEUL",
    "OEM_5",
    "OEM_PA3",
    "VOLUME_MUTE",
    "OEM_4",
    "LAUNCH_MAIL",
    "OEM_FJ_JISHO",
    "F3",
    "OEM_FJ_ROYA",
    "OEM_FJ_LOYA",
    "DOWN",
    "OEM_FINISH",
    "F5",
    "OEM_7",
    "F4",
    "F17",
    "NUMPAD1",
    "ICO_00",
    "NUMPAD8",
    "NUMPAD2",
    "LAUNCH_APP1",
    "BROWSER_FORWARD",
    "F7",
    "LAUNCH_APP2",
    "MULTIPLY",
    "EXECUTE",
    "BROWSER_FAVORITES",
    "NUMPAD6",
    "F16",
    "F10",
    "VOLUME_DOWN",
    "F20",
    "MEDIA_PREV_TRACK",
    "MODECHANGE",
    "F14",
    "NUMPAD3",
    "XBUTTON1",
    "F24",
    "XBUTTON2",
    "NUMPAD5",
    "NUMPAD4",
    "MEDIA_PLAY_PAUSE",
    "LAUNCH_MEDIA_SELECT",
    "F11",
    "OEM_102",
    "MEDIA_NEXT_TRACK",
    "NUMPAD7",
    "F21",
    "F13",
    "F12",
    "F23",
    "F22",
    "F15",
    "DIVIDE"
  };
#define stringpool ((const char *) &stringpool_contents)
#ifdef __GNUC__
__inline
#if defined __GNUC_STDC_INLINE__ || defined __GNUC_GNU_INLINE__
__attribute__ ((__gnu_inline__))
#endif
#endif
const struct vktable *
console_win32_vk (str, len)
     register const char *str;
     register unsigned int len;
{
  enum
    {
      TOTAL_KEYWORDS = 160,
      MIN_WORD_LENGTH = 2,
      MAX_WORD_LENGTH = 19,
      MIN_HASH_VALUE = 12,
      MAX_HASH_VALUE = 256
    };

  static const struct vktable wordlist[] =
    {
      {-1}, {-1}, {-1}, {-1}, {-1}, {-1}, {-1}, {-1}, {-1},
      {-1}, {-1}, {-1},
#line 40 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str12, VK_UP},
#line 52 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str13, VK_APPS},
#line 159 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str14, VK_CRSEL},
#line 34 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str15, VK_SPACE},
#line 95 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str16, VK_SCROLL},
#line 29 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str17, VK_ESCAPE},
#line 9 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str18, VK_CANCEL},
#line 32 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str19, VK_ACCEPT},
#line 66 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str20, VK_SEPARATOR},
#line 43 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str21, VK_SELECT},
#line 18 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str22, VK_CONTROL},
#line 166 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str23, VK_OEM_CLEAR},
#line 145 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str24, VK_OEM_RESET},
#line 155 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str25, VK_OEM_AUTO},
#line 151 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str26, VK_OEM_CUSEL},
      {-1},
#line 22 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str28, VK_KANA},
#line 127 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str29, VK_OEM_PLUS},
#line 35 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str30, VK_PRIOR},
#line 152 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str31, VK_OEM_ATTN},
#line 20 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str32, VK_PAUSE},
#line 13 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str33, VK_BACK},
#line 144 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str34, VK_PACKET},
#line 105 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str35, VK_RCONTROL},
#line 104 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str36, VK_LCONTROL},
#line 37 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str37, VK_END},
#line 38 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str38, VK_HOME},
#line 44 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str39, VK_PRINT},
#line 94 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str40, VK_NUMLOCK},
#line 39 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str41, VK_LEFT},
#line 25 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str42, VK_JUNJA},
#line 19 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str43, VK_MENU},
#line 150 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str44, VK_OEM_WSCTRL},
#line 156 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str45, VK_OEM_ENLW},
#line 36 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str46, VK_NEXT},
#line 51 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str47, VK_RWIN},
#line 50 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str48, VK_LWIN},
#line 21 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str49, VK_CAPITAL},
#line 49 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str50, VK_HELP},
#line 164 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str51, VK_NONAME},
#line 8 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str52, VK_RBUTTON},
#line 7 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str53, VK_LBUTTON},
#line 96 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str54, VK_OEM_NEC_EQUAL},
      {-1},
#line 47 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str56, VK_INSERT},
#line 27 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str57, VK_HANJA},
      {-1}, {-1},
#line 46 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str60, VK_SNAPSHOT},
#line 158 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str61, VK_ATTN},
#line 14 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str62, VK_TAB},
#line 157 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str63, VK_OEM_BACKTAB},
#line 143 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str64, VK_ICO_CLEAR},
#line 30 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str65, VK_CONVERT},
#line 16 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str66, VK_RETURN},
#line 146 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str67, VK_OEM_JUMP},
      {-1}, {-1}, {-1},
#line 111 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str71, VK_BROWSER_STOP},
#line 26 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str72, VK_FINAL},
#line 163 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str73, VK_ZOOM},
#line 28 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str74, VK_KANJI},
#line 48 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str75, VK_DELETE},
#line 128 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str76, VK_OEM_COMMA},
#line 67 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str77, VK_SUBTRACT},
      {-1},
#line 10 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str79, VK_MBUTTON},
#line 78 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str80, VK_F9},
#line 17 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str81, VK_SHIFT},
#line 103 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str82, VK_RSHIFT},
#line 102 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str83, VK_LSHIFT},
#line 65 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str84, VK_ADD},
#line 31 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str85, VK_NONCONVERT},
#line 160 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str86, VK_EXSEL},
#line 126 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str87, VK_OEM_1},
#line 138 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str88, VK_OEM_AX},
#line 108 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str89, VK_BROWSER_BACK},
#line 137 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str90, VK_OEM_8},
#line 129 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str91, VK_OEM_MINUS},
#line 162 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str92, VK_PLAY},
#line 131 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str93, VK_OEM_2},
#line 15 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str94, VK_CLEAR},
#line 99 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str95, VK_OEM_FJ_TOUROKU},
#line 147 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str96, VK_OEM_PA1},
#line 140 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str97, VK_ICO_HELP},
#line 112 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str98, VK_BROWSER_SEARCH},
#line 53 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str99, VK_SLEEP},
      {-1},
#line 70 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str101, VK_F1},
#line 148 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str102, VK_OEM_PA2},
#line 154 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str103, VK_OEM_COPY},
#line 77 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str104, VK_F8},
#line 88 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str105, VK_F19},
#line 41 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str106, VK_RIGHT},
#line 71 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str107, VK_F2},
#line 135 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str108, VK_OEM_6},
#line 87 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str109, VK_F18},
      {-1},
#line 117 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str111, VK_VOLUME_UP},
      {-1}, {-1},
#line 120 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str114, VK_MEDIA_STOP},
#line 130 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str115, VK_OEM_PERIOD},
      {-1},
#line 161 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str117, VK_EREOF},
      {-1}, {-1}, {-1},
#line 114 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str121, VK_BROWSER_HOME},
#line 75 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str122, VK_F6},
      {-1},
#line 110 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str124, VK_BROWSER_REFRESH},
      {-1},
#line 165 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str126, VK_PA1},
#line 142 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str127, VK_PROCESSKEY},
#line 68 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str128, VK_DECIMAL},
#line 132 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str129, VK_OEM_3},
#line 107 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str130, VK_RMENU},
#line 106 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str131, VK_LMENU},
#line 98 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str132, VK_OEM_FJ_MASSHOU},
#line 54 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str133, VK_NUMPAD0},
#line 24 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str134, VK_HANGUL},
#line 63 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str135, VK_NUMPAD9},
#line 23 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str136, VK_HANGEUL},
#line 134 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str137, VK_OEM_5},
#line 149 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str138, VK_OEM_PA3},
#line 115 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str139, VK_VOLUME_MUTE},
#line 133 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str140, VK_OEM_4},
#line 122 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str141, VK_LAUNCH_MAIL},
#line 97 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str142, VK_OEM_FJ_JISHO},
#line 72 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str143, VK_F3},
#line 101 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str144, VK_OEM_FJ_ROYA},
#line 100 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str145, VK_OEM_FJ_LOYA},
      {-1},
#line 42 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str147, VK_DOWN},
      {-1},
#line 153 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str149, VK_OEM_FINISH},
      {-1},
#line 74 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str151, VK_F5},
      {-1},
#line 136 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str153, VK_OEM_7},
#line 73 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str154, VK_F4},
#line 86 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str155, VK_F17},
#line 55 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str156, VK_NUMPAD1},
#line 141 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str157, VK_ICO_00},
      {-1},
#line 62 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str159, VK_NUMPAD8},
      {-1}, {-1},
#line 56 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str162, VK_NUMPAD2},
      {-1},
#line 124 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str164, VK_LAUNCH_APP1},
#line 109 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str165, VK_BROWSER_FORWARD},
      {-1},
#line 76 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str167, VK_F7},
      {-1}, {-1},
#line 125 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str170, VK_LAUNCH_APP2},
#line 64 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str171, VK_MULTIPLY},
      {-1}, {-1},
#line 45 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str174, VK_EXECUTE},
      {-1},
#line 113 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str176, VK_BROWSER_FAVORITES},
#line 60 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str177, VK_NUMPAD6},
      {-1},
#line 85 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str179, VK_F16},
      {-1}, {-1},
#line 79 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str182, VK_F10},
      {-1}, {-1},
#line 116 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str185, VK_VOLUME_DOWN},
      {-1}, {-1},
#line 89 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str188, VK_F20},
#line 119 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str189, VK_MEDIA_PREV_TRACK},
      {-1},
#line 33 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str191, VK_MODECHANGE},
      {-1}, {-1}, {-1}, {-1}, {-1},
#line 83 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str197, VK_F14},
#line 57 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str198, VK_NUMPAD3},
#line 11 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str199, VK_XBUTTON1},
      {-1}, {-1}, {-1},
#line 93 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str203, VK_F24},
      {-1},
#line 12 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str205, VK_XBUTTON2},
#line 59 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str206, VK_NUMPAD5},
      {-1}, {-1},
#line 58 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str209, VK_NUMPAD4},
      {-1}, {-1}, {-1}, {-1}, {-1},
#line 121 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str215, VK_MEDIA_PLAY_PAUSE},
      {-1},
#line 123 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str217, VK_LAUNCH_MEDIA_SELECT},
#line 80 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str218, VK_F11},
      {-1},
#line 139 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str220, VK_OEM_102},
#line 118 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str221, VK_MEDIA_NEXT_TRACK},
#line 61 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str222, VK_NUMPAD7},
      {-1},
#line 90 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str224, VK_F21},
      {-1},
#line 82 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str226, VK_F13},
      {-1}, {-1},
#line 81 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str229, VK_F12},
      {-1}, {-1},
#line 92 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str232, VK_F23},
      {-1}, {-1},
#line 91 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str235, VK_F22},
      {-1}, {-1}, {-1}, {-1}, {-1}, {-1},
#line 84 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str242, VK_F15},
      {-1}, {-1}, {-1}, {-1}, {-1}, {-1}, {-1}, {-1}, {-1},
      {-1}, {-1}, {-1}, {-1},
#line 69 "win32_vk.list"
      {(int)(long)&((struct stringpool_t *)0)->stringpool_str256, VK_DIVIDE}
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register int o = wordlist[key].ofs;
          if (o >= 0)
            {
              register const char *s = o + stringpool;

              if ((((unsigned char)*str ^ (unsigned char)*s) & ~32) == 0 && !gperf_case_strcmp (str, s))
                return &wordlist[key];
            }
        }
    }
  return 0;
}
