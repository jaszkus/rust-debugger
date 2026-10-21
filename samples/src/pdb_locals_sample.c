struct Node {
    int id;
    struct Node *next;
};

struct Point {
    int x;
    int y;
};

int add_points(struct Point a, struct Point b) {
    int sum = a.x + b.y;
    return sum;
}

int compute(struct Node *n, struct Point p) {
    int value = p.x;
    if (n) {
        value += n->id;
    }
    return value;
}

int main(void) {
    struct Node n;
    struct Point p;
    int result;

    n.id = 5;
    n.next = 0;
    p.x = 1;
    p.y = 2;
    result = compute(&n, p);
    result += add_points(p, p);
    return result;
}
