//! Source for `samples/src/pdb_sample.exe` + `samples/src/pdb_sample.pdb` — rebuild with:
//!   clang --target=x86_64-pc-windows-msvc -g -gcodeview -O0 -c samples/src/pdb_sample.c -o pdb.obj
//!   lld-link pdb.obj /DEBUG:FULL /OUT:samples/src/pdb_sample.exe /PDB:samples/src/pdb_sample.pdb \
//!       /NODEFAULTLIB /ENTRY:main /SUBSYSTEM:console
//! Covers: struct with pointer cycle (Node.next), struct-by-value param
//! (Point), enum used in a signature (Color), union (Mixed).

struct Node { int id; struct Node *next; };
enum Color { RED, BLUE = 255 };
typedef struct Point { int x; int y; } Point;
union Mixed { int i; float f; };

int compute(struct Node *n, Point p, enum Color c) {
    union Mixed m; m.i = p.x;
    if (!n) return (int)c + m.i;
    return n->id + p.y;
}

int main(void) { struct Node n = {5, 0}; Point pt = {1, 2}; return compute(&n, pt, BLUE); }
