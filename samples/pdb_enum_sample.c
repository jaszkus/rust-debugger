enum Color { RED = 1, GREEN = 2, BLUE = 4 };

struct Flags {
    unsigned a : 3;
    unsigned b : 5;
    enum Color color;
};

int classify(struct Flags f) {
    return (int)f.a + (int)f.b + (int)f.color;
}

int main(void) {
    struct Flags f;
    f.a = 3;
    f.b = 7;
    f.color = GREEN;
    return classify(f);
}
