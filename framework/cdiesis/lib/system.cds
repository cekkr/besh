// system.cds - The cDiesis System library.
//
// STATUS: experimental standard library. This cDiesis source is compiled by
// framework/cdiesis/parser.bsh at framework load time and exercised by the
// repository suite. It is not BSH and the shell cannot execute it directly.
//
// Everything here is ordinary cDiesis: there is no privileged "built-in class"
// mechanism. The library reaches the outside world exactly the way user code
// does - through extern declarations that compile to the HOST opcode.

namespace System;

extern "bsh" void print(string text);
extern "bsh" int strlen(string text);
extern "bsh" string substr(string text, int start, int length);
extern "bsh" string charat(string text, int index);
extern "bsh" int indexof(string text, string needle);

class Console {
    public static void WriteLine(string text) {
        print(text);
    }

    public static void Write(string text) {
        // The shell's echo always terminates the line, so Write and WriteLine
        // coincide until a host primitive for partial output exists.
        print(text);
    }

    public static void WriteValue(string label, string value) {
        print(label + value);
    }
}

class Math {
    public static int Abs(int value) {
        if (value < 0) {
            return 0 - value;
        }
        return value;
    }

    public static int Max(int a, int b) {
        if (a > b) {
            return a;
        }
        return b;
    }

    public static int Min(int a, int b) {
        if (a < b) {
            return a;
        }
        return b;
    }

    public static int Pow(int baseValue, int exponent) {
        int result = 1;
        int i = 0;
        while (i < exponent) {
            result = result * baseValue;
            i = i + 1;
        }
        return result;
    }

    public static int Clamp(int value, int low, int high) {
        return Max(low, Min(high, value));
    }
}

class Convert {
    public static string ToString(object value) {
        return "" + value;
    }

    public static int ToInt(string text) {
        // The cast is what performs the check: a non-numeric string traps in
        // cds_cast rather than silently becoming zero.
        return (int)text;
    }

    public static bool ToBool(string text) {
        if (text == "true") {
            return true;
        }
        if (text == "1") {
            return true;
        }
        return false;
    }
}

class Str {
    public static int Length(string text) {
        return strlen(text);
    }

    public static string Sub(string text, int start, int length) {
        return substr(text, start, length);
    }

    public static string CharAt(string text, int index) {
        return charat(text, index);
    }

    public static int IndexOf(string text, string needle) {
        return indexof(text, needle);
    }

    public static bool StartsWith(string text, string prefix) {
        int n = strlen(prefix);
        if (strlen(text) < n) {
            return false;
        }
        return substr(text, 0, n) == prefix;
    }

    public static string Repeat(string text, int times) {
        string result = "";
        int i = 0;
        while (i < times) {
            result = result + text;
            i = i + 1;
        }
        return result;
    }
}
