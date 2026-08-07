// inventory.cds - Generics, dictionaries, foreach and string building.
//
// STATUS: demonstration source executed by tests/cdiesis_stdlib.bsh.
//
// The interesting part is what is NOT here: no array type, no hash table, no
// iterator protocol. List<T> and Dictionary<K,V> are ordinary cDiesis classes
// from framework/cdiesis/lib/collections.cds whose storage is mangled shell
// variables, and 'foreach' lowers to an index loop over Count/Get.

namespace Demo.Inventory;

using System;
using System.Collections;
using System.Text;

class Item {
    public string Sku;
    public string Label;
    public int Quantity;
    public int UnitPrice;

    public Item(string sku, string label, int quantity, int unitPrice) {
        this.Sku = sku;
        this.Label = label;
        this.Quantity = quantity;
        this.UnitPrice = unitPrice;
    }

    public int Total() {
        return this.Quantity * this.UnitPrice;
    }

    public override string ToString() {
        return this.Sku + " " + this.Label
             + " x" + Convert.ToString(this.Quantity)
             + " = " + Convert.ToString(this.Total());
    }
}

class Inventory {
    public List<Item> items;
    public Dictionary<string, Item> bySku;

    public Inventory() {
        this.items = new List<Item>();
        this.bySku = new Dictionary<string, Item>();
    }

    public void Add(Item item) {
        this.items.Add(item);
        this.bySku.Set(item.Sku, item);
    }

    public Item Find(string sku) {
        return this.bySku.Get(sku);
    }

    public int Value() {
        int total = 0;
        foreach (Item item in this.items) {
            total = total + item.Total();
        }
        return total;
    }

    public List<Item> LowStock(int threshold) {
        List<Item> result = new List<Item>();
        foreach (Item item in this.items) {
            if (item.Quantity < threshold) {
                result.Add(item);
            }
        }
        return result;
    }

    public string Report() {
        StringBuilder out = new StringBuilder();
        out.AppendLine("inventory report");
        foreach (Item item in this.items) {
            out.AppendLine("  " + item.ToString());
        }
        out.Append("total value = ");
        out.Append(Convert.ToString(this.Value()));
        return out.ToString();
    }
}

class InventoryDemo {
    public static int Main() {
        Inventory stock = new Inventory();
        stock.Add(new Item("A-1", "resistor", 250, 2));
        stock.Add(new Item("B-2", "capacitor", 40, 7));
        stock.Add(new Item("C-3", "crystal", 3, 45));

        Console.WriteLine(stock.Report());

        Item found = stock.Find("B-2");
        if (found != null) {
            Console.WriteValue("found: ", found.ToString());
        }

        List<Item> low = stock.LowStock(50);
        Console.WriteValue("low stock count = ", Convert.ToString(low.Count()));
        foreach (Item item in low) {
            Console.WriteValue("  reorder ", item.Label);
        }

        // 'var' is inference, not dynamic typing: the compiler pins the slot to
        // the static type the initialiser produced.
        var value = stock.Value();
        return value;
    }
}
