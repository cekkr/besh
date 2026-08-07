// text.cds - The cDiesis Text library.
//
// STATUS: experimental standard library, compiled and exercised by the suite.
//
// StringBuilder exists here for the same reason it exists in C#: repeated
// concatenation of immutable strings is the wrong shape. Under B[e]SH the cost
// is different (every value is already a string) but the abstraction still pays
// for itself, because it gives the future compiler one obvious place to
// specialise - a single Append loop instead of a chain of BIN + ops.

namespace System.Text;

extern "bsh" int strlen(string text);
extern "bsh" string substr(string text, int start, int length);
extern "bsh" string charat(string text, int index);

class StringBuilder {
    public string buffer;

    public StringBuilder() {
        this.buffer = "";
    }

    public StringBuilder Append(string text) {
        this.buffer = this.buffer + text;
        return this;
    }

    public StringBuilder AppendLine(string text) {
        this.buffer = this.buffer + text + "\n";
        return this;
    }

    public StringBuilder AppendPair(string key, string value) {
        this.buffer = this.buffer + key + "=" + value + ";";
        return this;
    }

    public int Length() {
        return strlen(this.buffer);
    }

    public void Clear() {
        this.buffer = "";
    }

    public override string ToString() {
        return this.buffer;
    }
}

class TextUtil {
    public static string Reverse(string text) {
        string result = "";
        int i = strlen(text) - 1;
        while (i >= 0) {
            result = result + charat(text, i);
            i = i - 1;
        }
        return result;
    }

    public static bool IsPalindrome(string text) {
        return Reverse(text) == text;
    }

    public static string PadLeft(string text, int width, string filler) {
        string result = text;
        while (strlen(result) < width) {
            result = filler + result;
        }
        return result;
    }

    public static int CountChar(string text, string needle) {
        int count = 0;
        int i = 0;
        int n = strlen(text);
        while (i < n) {
            if (charat(text, i) == needle) {
                count = count + 1;
            }
            i = i + 1;
        }
        return count;
    }

    public static string Trim(string text) {
        int start = 0;
        int end = strlen(text);
        while (start < end) {
            if (charat(text, start) != " ") {
                break;
            }
            start = start + 1;
        }
        while (end > start) {
            if (charat(text, end - 1) != " ") {
                break;
            }
            end = end - 1;
        }
        return substr(text, start, end - start);
    }
}
