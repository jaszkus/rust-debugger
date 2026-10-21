int _fltused = 1;

double add(double a, double b) {
    double sum = a + b;
    return sum;
}

double scale(double x) {
    return x * 2.0;
}

int main(void) {
    double x = 1.5;
    double y = 2.5;
    double z = add(x, y);
    return (int)scale(z);
}
