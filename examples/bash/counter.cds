// A cDiesis library consumed from ordinary Bash through cdiesis.sh.
class Counter {
    public int Value;
    public string Label;

    public Counter(int initial) {
        this.Value = initial;
        this.Label = "counter";
    }

    public int Add(int amount) {
        this.Value = this.Value + amount;
        return this.Value;
    }

    public int Read() {
        return this.Value;
    }
}
