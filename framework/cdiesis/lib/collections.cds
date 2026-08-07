// collections.cds - The cDiesis Collections library.
//
// STATUS: experimental standard library, compiled and exercised by the suite.
//
// This file is the clearest demonstration of the framework's claim. A generic
// list, a dictionary and a stack - types that usually need a heap, a memory
// layout and a garbage collector - are built here out of exactly two shell
// primitives: a named string variable and string concatenation. Element storage
// is a mangled variable name, "CDSL_<listId>_<index>", written through the same
// setvar/getvar host functions any user program could declare.
//
// Generics are erased (List<int> compiles to the flat type name "List$int"), so
// there is one compiled body per generic class, not one per instantiation.

namespace System.Collections;

extern "bsh" string getvar(string name);
extern "bsh" string setvar(string name, string value);
extern "bsh" void print(string text);

class List {
    public static int NextId;

    public int Id;
    public int Size;
    public string ElementType;

    public List() {
        NextId = NextId + 1;
        this.Id = NextId;
        this.Size = 0;
        this.ElementType = "object";
    }

    public string SlotName(int index) {
        return "CDSL_" + this.Id + "_" + index;
    }

    public int Count() {
        return this.Size;
    }

    public void Add(object item) {
        setvar(this.SlotName(this.Size), item);
        this.Size = this.Size + 1;
    }

    public object Get(int index) {
        if (index < 0) {
            return null;
        }
        if (index >= this.Size) {
            return null;
        }
        return getvar(this.SlotName(index));
    }

    public void Set(int index, object value) {
        if (index < 0) {
            return;
        }
        if (index >= this.Size) {
            return;
        }
        setvar(this.SlotName(index), value);
    }

    public int IndexOf(object item) {
        int i = 0;
        while (i < this.Size) {
            if (this.Get(i) == item) {
                return i;
            }
            i = i + 1;
        }
        return 0 - 1;
    }

    public bool Contains(object item) {
        return this.IndexOf(item) >= 0;
    }

    // Removal compacts in place: no free list, because a slot is just a
    // variable and clearing it is a store of the empty string.
    public void RemoveAt(int index) {
        int i = index;
        int last = this.Size - 1;
        while (i < last) {
            setvar(this.SlotName(i), this.Get(i + 1));
            i = i + 1;
        }
        setvar(this.SlotName(last), "");
        this.Size = this.Size - 1;
    }

    public void Clear() {
        int i = 0;
        while (i < this.Size) {
            setvar(this.SlotName(i), "");
            i = i + 1;
        }
        this.Size = 0;
    }

    public string Join(string separator) {
        string result = "";
        int i = 0;
        while (i < this.Size) {
            if (i > 0) {
                result = result + separator;
            }
            result = result + this.Get(i);
            i = i + 1;
        }
        return result;
    }

    public override string ToString() {
        return "[" + this.Join(", ") + "]";
    }
}

class Stack {
    public List items;

    public Stack() {
        this.items = new List();
    }

    public int Count() {
        return this.items.Count();
    }

    public void Push(object value) {
        this.items.Add(value);
    }

    public object Pop() {
        int last = this.items.Count() - 1;
        if (last < 0) {
            return null;
        }
        object value = this.items.Get(last);
        this.items.RemoveAt(last);
        return value;
    }

    public object Peek() {
        int last = this.items.Count() - 1;
        if (last < 0) {
            return null;
        }
        return this.items.Get(last);
    }
}

// Keys and values live in two parallel lists. A hash table would need an array
// primitive and an integer hash; the parallel-list form needs neither and keeps
// every operation expressible in the seventeen opcodes.
class Dictionary {
    public List keys;
    public List values;

    public Dictionary() {
        this.keys = new List();
        this.values = new List();
    }

    public int Count() {
        return this.keys.Count();
    }

    public bool ContainsKey(string key) {
        return this.keys.IndexOf(key) >= 0;
    }

    public void Set(string key, object value) {
        int at = this.keys.IndexOf(key);
        if (at < 0) {
            this.keys.Add(key);
            this.values.Add(value);
            return;
        }
        this.values.Set(at, value);
    }

    public object Get(string key) {
        int at = this.keys.IndexOf(key);
        if (at < 0) {
            return null;
        }
        return this.values.Get(at);
    }

    public string KeyAt(int index) {
        return this.keys.Get(index);
    }

    public void Dump(string title) {
        print(title);
        int i = 0;
        while (i < this.keys.Count()) {
            print("  " + this.keys.Get(i) + " = " + this.values.Get(i));
            i = i + 1;
        }
    }
}
