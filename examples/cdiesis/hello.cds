// hello.cds - The smallest complete cDiesis unit.
//
// STATUS: demonstration source executed by tests/cdiesis_stdlib.bsh.
//
// Run it from BSH with:
//   import cdiesis
//   lang_load "cdiesis" ok
//   lang_eval "cdiesis" HELLO_SRC result     # HELLO_SRC holds this text

namespace Demo;

using System;

class Hello {
    public static string Greet(string who) {
        string message = "Hello, " + who + "!";
        Console.WriteLine(message);
        return message;
    }

    public static int Main() {
        Greet("B[e]SH");

        // Typed locals are checked at compile time and stored as strings at
        // runtime; the type never changes where the value lives.
        int answer = 6 * 7;
        Console.WriteValue("answer = ", Convert.ToString(answer));

        int i = 0;
        int total = 0;
        while (i < 10) {
            total = total + i;
            i = i + 1;
        }
        Console.WriteValue("sum 0..9 = ", Convert.ToString(total));

        return total;
    }
}
