// shapes.cds - Classes, single inheritance, virtual dispatch and polymorphic
// collections in cDiesis.
//
// STATUS: demonstration source executed by tests/cdiesis_stdlib.bsh.
//
// What to look at: every construct below - the base class, the two overrides,
// the polymorphic loop - compiles to the same seventeen opcodes as the "hello"
// example. Inheritance adds no opcode; it only changes which class the runtime
// finds first when it walks for a method body (cds_method_owner).
//
// Inspect the lowering from BSH after compiling this unit:
//   cds_dump_ops Circle Area
//   cds_dump_ops ShapeReport Run

namespace Demo.Shapes;

using System;
using System.Collections;
using System.Text;

class Shape {
    public string Name;

    public Shape(string name) {
        this.Name = name;
    }

    public virtual int Area() {
        return 0;
    }

    public virtual string Describe() {
        return this.Name + " with area " + Convert.ToString(this.Area());
    }

    public override string ToString() {
        return this.Describe();
    }
}

class Rectangle : Shape {
    public int Width;
    public int Height;

    public Rectangle(int width, int height) {
        this.Name = "rectangle";
        this.Width = width;
        this.Height = height;
    }

    public override int Area() {
        return this.Width * this.Height;
    }

    public bool IsSquare() {
        return this.Width == this.Height;
    }
}

class Square : Rectangle {
    public Square(int side) {
        this.Name = "square";
        this.Width = side;
        this.Height = side;
    }

    // Two levels of inheritance, resolved by the same single walk: Square has
    // no Area, so Rectangle's body runs - with Square's fields.
    public override string Describe() {
        return "square of side " + Convert.ToString(this.Width)
             + " and area " + Convert.ToString(this.Area());
    }
}

class Circle : Shape {
    public int Radius;

    public Circle(int radius) {
        this.Name = "circle";
        this.Radius = radius;
    }

    // Integer arithmetic on purpose: cDiesis borrows the shell's own numeric
    // handlers, so "22 / 7" truncates here exactly as it would in BSH.
    public override int Area() {
        return 22 * this.Radius * this.Radius / 7;
    }
}

class ShapeReport {
    public static int Run() {
        List shapes = new List();
        shapes.Add(new Rectangle(3, 4));
        shapes.Add(new Square(5));
        shapes.Add(new Circle(2));

        int total = 0;
        StringBuilder report = new StringBuilder();

        foreach (Shape shape in shapes) {
            // Virtual dispatch: the slot's static type is Shape, the body that
            // runs belongs to the runtime class.
            report.AppendLine(shape.Describe());
            total = total + shape.Area();
        }

        Console.WriteLine(report.ToString());
        Console.WriteValue("total area = ", Convert.ToString(total));

        int largest = 0;
        int i = 0;
        while (i < shapes.Count()) {
            Shape current = shapes.Get(i);
            largest = Math.Max(largest, current.Area());
            i = i + 1;
        }
        Console.WriteValue("largest area = ", Convert.ToString(largest));

        return total;
    }
}
