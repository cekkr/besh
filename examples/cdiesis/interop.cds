// interop.cds - One unit talking to two other languages.
//
// STATUS: demonstration source, not a test. Never executed.
//
// Three languages appear in this file's execution path and only one of them is
// cDiesis:
//   * "bsh"     the host shell, reached through the built-in host functions;
//   * "rpn"     the stack language in framework/rpn.bsh, whose words are
//               defined by examples/cdiesis/mixed_languages.bsh;
//   * "cdiesis" this unit itself, which the RPN program calls back into.
//
// Every one of those calls compiles to a single HOST op. cDiesis has no
// knowledge of RPN's evaluator, RPN has no knowledge of the cDiesis heap, and
// neither has to be loaded when the other is compiled - only when the call runs.

namespace Demo.Interop;

using System;
using System.Collections;

// The shell. 'getvar'/'setvar' reach scoped BSH variables by name; 'print'
// writes through echo.
extern "bsh" void print(string text);
extern "bsh" string getvar(string name);
extern "bsh" string setvar(string name, string value);

// The other loadable language. These words must exist in the RPN dictionary at
// call time; if the framework is unloaded the call fails loudly instead of
// silently falling back, which is the property the boundary is designed for.
extern "rpn" int square(int value);
extern "rpn" int hypotSquares(int a, int b);

class Bridge {
    // Called BY the RPN program (and by plain BSH) through:
    //   lang_arg_reset; lang_arg_push "7"; lang_call "cdiesis" "Bridge.Triple" out
    public static int Triple(int value) {
        return value * 3;
    }

    public static string Describe(string label, int value) {
        return label + "=" + Convert.ToString(value);
    }
}

class InteropDemo {
    public static int Main() {
        // cDiesis -> RPN
        int squared = square(9);
        Console.WriteValue("rpn square(9) = ", Convert.ToString(squared));

        int hyp = hypotSquares(3, 4);
        Console.WriteValue("rpn hypotSquares(3,4) = ", Convert.ToString(hyp));

        // cDiesis -> BSH, and back again: the shell variable written here is an
        // ordinary scoped BSH variable that a later BSH line can read.
        setvar("CDS_DEMO_RESULT", Convert.ToString(hyp));
        string echoed = getvar("CDS_DEMO_RESULT");
        print("bsh sees CDS_DEMO_RESULT = " + echoed);

        // cDiesis -> cDiesis, for contrast: a plain CALL, no boundary at all.
        int tripled = Bridge.Triple(hyp);
        Console.WriteValue("Bridge.Triple = ", Convert.ToString(tripled));

        List results = new List();
        results.Add(Bridge.Describe("squared", squared));
        results.Add(Bridge.Describe("hyp", hyp));
        results.Add(Bridge.Describe("tripled", tripled));
        Console.WriteLine(results.ToString());

        return tripled;
    }
}
