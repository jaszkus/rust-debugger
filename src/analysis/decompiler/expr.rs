#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    #[allow(dead_code)]
    Sar,
}

impl BinOp {
    pub fn sym(self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Xor => "^",
            BinOp::Shl => "<<",
            BinOp::Shr => ">>",
            BinOp::Sar => ">>",
        }
    }

    fn prec(self) -> u8 {
        match self {
            BinOp::Or => 1,
            BinOp::Xor => 2,
            BinOp::And => 3,
            BinOp::Shl | BinOp::Shr | BinOp::Sar => 4,
            BinOp::Add | BinOp::Sub => 5,
            BinOp::Mul | BinOp::Div => 6,
        }
    }

    fn strict_right(self) -> bool {
        matches!(
            self,
            BinOp::Sub | BinOp::Div | BinOp::Shl | BinOp::Shr | BinOp::Sar
        )
    }

    fn commutative(self) -> bool {
        matches!(
            self,
            BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
        )
    }

    pub fn from_sym(sym: &str) -> Option<BinOp> {
        Some(match sym {
            "+" => BinOp::Add,
            "-" => BinOp::Sub,
            "*" => BinOp::Mul,
            "/" => BinOp::Div,
            "&" => BinOp::And,
            "|" => BinOp::Or,
            "^" => BinOp::Xor,
            "<<" => BinOp::Shl,
            ">>" => BinOp::Shr,
            _ => return None,
        })
    }

    fn fold(self, x: i64, y: i64) -> i64 {
        match self {
            BinOp::Add => x.wrapping_add(y),
            BinOp::Sub => x.wrapping_sub(y),
            BinOp::Mul => x.wrapping_mul(y),
            BinOp::Div => {
                if y == 0 {
                    0
                } else {
                    x.wrapping_div(y)
                }
            }
            BinOp::And => x & y,
            BinOp::Or => x | y,
            BinOp::Xor => x ^ y,
            BinOp::Shl => x.wrapping_shl((y as u32) & 63),
            BinOp::Shr => ((x as u64).wrapping_shr((y as u32) & 63)) as i64,
            BinOp::Sar => x.wrapping_shr((y as u32) & 63),
        }
    }
}

pub(crate) fn fmt_const(c: i64) -> String {
    if c < 0 {
        match c.checked_neg() {
            Some(pos) if pos > 9 => format!("-{:#x}", pos),
            Some(pos) => format!("-{}", pos),
            None => "(-0x8000000000000000)".into(),
        }
    } else if c > 9 {
        format!("{:#x}", c)
    } else {
        format!("{}", c)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    C(i64),
    Var(String),
    Bin {
        op: BinOp,
        a: Box<Expr>,
        b: Box<Expr>,
    },
}

impl Expr {
    pub fn c(v: i64) -> Expr {
        Expr::C(v)
    }

    pub fn var(s: impl Into<String>) -> Expr {
        Expr::Var(s.into())
    }

    pub fn bin(op: BinOp, a: Expr, b: Expr) -> Expr {
        Expr::Bin {
            op,
            a: Box::new(a),
            b: Box::new(b),
        }
    }

    pub fn uses_var(&self, name: &str) -> bool {
        match self {
            Expr::C(_) => false,
            Expr::Var(s) => s == name,
            Expr::Bin { a, b, .. } => a.uses_var(name) || b.uses_var(name),
        }
    }

    pub fn from_sym(op_sym: &str, a: Expr, b: Expr) -> Option<Expr> {
        BinOp::from_sym(op_sym).map(|op| Expr::bin(op, a, b))
    }

    pub fn len_bound(&self, limit: usize) -> usize {
        fn go(e: &Expr, acc: &mut usize, limit: usize) {
            if *acc > limit {
                return;
            }
            match e {
                Expr::C(_) => *acc += 21,
                Expr::Var(s) => *acc += s.len(),
                Expr::Bin { a, b, .. } => {
                    *acc += 6;
                    go(a, acc, limit);
                    go(b, acc, limit);
                }
            }
        }
        let mut acc = 0usize;
        go(self, &mut acc, limit);
        acc
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, 0);
        s
    }

    fn write(&self, out: &mut String, parent_prec: u8) {
        match self {
            Expr::C(c) => out.push_str(&fmt_const(*c)),
            Expr::Var(s) => out.push_str(s),
            Expr::Bin { op, a, b } => {
                let prec = op.prec();
                let parens = prec < parent_prec;
                if parens {
                    out.push('(');
                }
                let (left_prec, right_prec) = if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar)
                {
                    (prec + 2, prec + 2)
                } else {
                    (prec, if op.strict_right() { prec + 1 } else { prec })
                };
                a.write(out, left_prec);
                out.push(' ');
                out.push_str(op.sym());
                out.push(' ');
                b.write(out, right_prec);
                if parens {
                    out.push(')');
                }
            }
        }
    }

    pub fn simplify(self) -> Expr {
        let mut e = self;
        for _ in 0..10 {
            let before = e.clone();
            e = e.step();
            if e == before {
                break;
            }
        }
        e
    }

    fn step(self) -> Expr {
        match self {
            Expr::Bin { op, a, b } => {
                let a = a.step();
                let b = b.step();
                simplify_bin(op, a, b)
            }
            other => other,
        }
    }
}

fn simplify_bin(op: BinOp, a: Expr, b: Expr) -> Expr {
    if let (Expr::C(x), Expr::C(y)) = (&a, &b) {
        if !(matches!(op, BinOp::Div) && *y == 0) {
            return Expr::C(op.fold(*x, *y));
        }
    }
    let is_c = |e: &Expr, v: i64| matches!(e, Expr::C(c) if *c == v);
    let same = a == b;

    match op {
        BinOp::Add => {
            if is_c(&b, 0) {
                return a;
            }
            if is_c(&a, 0) {
                return b;
            }
            if let (
                Expr::Bin {
                    op: BinOp::Add,
                    a: x,
                    b: c1,
                },
                Expr::C(c2),
            ) = (&a, &b)
            {
                if let Expr::C(c1v) = &**c1 {
                    return Expr::bin(BinOp::Add, (**x).clone(), Expr::C(c1v.wrapping_add(*c2)));
                }
            }
            if let (
                Expr::Bin {
                    op: BinOp::Add,
                    a: c1,
                    b: x,
                },
                Expr::C(c2),
            ) = (&a, &b)
            {
                if let Expr::C(c1v) = &**c1 {
                    return Expr::bin(BinOp::Add, (**x).clone(), Expr::C(c1v.wrapping_add(*c2)));
                }
            }
            if let (Expr::C(_), _) = (&a, &b) {
                return Expr::bin(op, b, a);
            }
        }
        BinOp::Sub => {
            if is_c(&b, 0) {
                return a;
            }
            if same {
                return Expr::C(0);
            }
            if let Expr::C(c) = &b {
                return Expr::bin(BinOp::Add, a, Expr::C(c.wrapping_neg()));
            }
            if let (
                Expr::Bin {
                    op: BinOp::Sub,
                    a: x,
                    b: c1,
                },
                Expr::C(c2),
            ) = (&a, &b)
            {
                if let Expr::C(c1v) = &**c1 {
                    return Expr::bin(BinOp::Sub, (**x).clone(), Expr::C(c1v.wrapping_add(*c2)));
                }
            }
        }
        BinOp::Mul => {
            if is_c(&b, 1) {
                return a;
            }
            if is_c(&a, 1) {
                return b;
            }
            if is_c(&a, 0) || is_c(&b, 0) {
                return Expr::C(0);
            }
            if is_c(&b, -1) {
                return Expr::bin(BinOp::Sub, Expr::C(0), a);
            }
            if let Expr::C(c) = &b {
                if *c > 0 && (*c as u64).is_power_of_two() {
                    return Expr::bin(BinOp::Shl, a, Expr::C(c.trailing_zeros() as i64));
                }
            }
            if let (Expr::C(_), _) = (&a, &b) {
                return Expr::bin(op, b, a);
            }
        }
        BinOp::Div => {
            if is_c(&b, 1) {
                return a;
            }
            if is_c(&a, 0) {
                return Expr::C(0);
            }
        }
        BinOp::And => {
            if is_c(&a, 0) || is_c(&b, 0) {
                return Expr::C(0);
            }
            if is_c(&b, -1) {
                return a;
            }
            if is_c(&a, -1) {
                return b;
            }
            if same {
                return a;
            }
            if let (
                Expr::Bin {
                    op: BinOp::And,
                    a: x,
                    b: c1,
                },
                Expr::C(c2),
            ) = (&a, &b)
            {
                if let Expr::C(c1v) = &**c1 {
                    return Expr::bin(BinOp::And, (**x).clone(), Expr::C(c1v & c2));
                }
            }
            if let (
                Expr::Bin {
                    op: BinOp::Shl,
                    a: _x,
                    b: c1,
                },
                Expr::C(m),
            ) = (&a, &b)
            {
                if let Expr::C(c) = &**c1 {
                    if *c > 0 && *c < 64 && *m == (!0i64).wrapping_shl(*c as u32) {
                        return a;
                    }
                }
            }
            if let (Expr::C(_), _) = (&a, &b) {
                return Expr::bin(op, b, a);
            }
        }
        BinOp::Or => {
            if is_c(&b, 0) {
                return a;
            }
            if is_c(&a, 0) {
                return b;
            }
            if is_c(&a, -1) || is_c(&b, -1) {
                return Expr::C(-1);
            }
            if same {
                return a;
            }
            if let (
                Expr::Bin {
                    op: BinOp::Or,
                    a: x,
                    b: c1,
                },
                Expr::C(c2),
            ) = (&a, &b)
            {
                if let Expr::C(c1v) = &**c1 {
                    return Expr::bin(BinOp::Or, (**x).clone(), Expr::C(c1v | c2));
                }
            }
            if let (Expr::C(_), _) = (&a, &b) {
                return Expr::bin(op, b, a);
            }
        }
        BinOp::Xor => {
            if is_c(&b, 0) {
                return a;
            }
            if is_c(&a, 0) {
                return b;
            }
            if same {
                return Expr::C(0);
            }
            if let Expr::Bin {
                op: BinOp::Xor,
                a: p,
                b: q,
            } = &a
            {
                if q.as_ref() == &b {
                    return p.as_ref().clone();
                }
                if p.as_ref() == &b {
                    return q.as_ref().clone();
                }
            }
            if let Expr::Bin {
                op: BinOp::Xor,
                a: p,
                b: q,
            } = &b
            {
                if q.as_ref() == &a {
                    return p.as_ref().clone();
                }
                if p.as_ref() == &a {
                    return q.as_ref().clone();
                }
            }
            if let (
                Expr::Bin {
                    op: BinOp::Xor,
                    a: x,
                    b: c1,
                },
                Expr::C(c2),
            ) = (&a, &b)
            {
                if let Expr::C(c1v) = &**c1 {
                    return Expr::bin(BinOp::Xor, (**x).clone(), Expr::C(c1v ^ c2));
                }
            }
            if let (Expr::C(_), _) = (&a, &b) {
                return Expr::bin(op, b, a);
            }
        }
        BinOp::Shl | BinOp::Shr | BinOp::Sar => {
            if is_c(&b, 0) {
                return a;
            }
            if is_c(&a, 0) {
                return Expr::C(0);
            }
            if let Expr::Bin {
                op: op2,
                a: x,
                b: c1e,
            } = &a
            {
                if *op2 == op {
                    if let Expr::C(c1) = &**c1e {
                        if let Expr::C(c2) = &b {
                            let combined = (*c1).wrapping_add(*c2);
                            if (0..64).contains(&combined) {
                                return Expr::bin(op, (**x).clone(), Expr::C(combined));
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = same;
    let _ = op.commutative();
    Expr::bin(op, a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(e: Expr) -> String {
        e.simplify().render()
    }

    #[test]
    fn folds_constants_nested() {
        let e = Expr::bin(
            BinOp::Add,
            Expr::bin(BinOp::Mul, Expr::C(2), Expr::C(3)),
            Expr::C(4),
        );
        assert_eq!(r(e), "0xa");
    }

    #[test]
    fn identities() {
        let x = || Expr::var("rcx");
        let y = || Expr::var("rdx");
        assert_eq!(r(Expr::bin(BinOp::Add, x(), Expr::C(0))), "rcx");
        assert_eq!(r(Expr::bin(BinOp::Sub, x(), x())), "0");
        assert_eq!(r(Expr::bin(BinOp::Mul, x(), Expr::C(1))), "rcx");
        assert_eq!(r(Expr::bin(BinOp::And, x(), Expr::C(-1))), "rcx");
        assert_eq!(r(Expr::bin(BinOp::Or, x(), x())), "rcx");
        assert_eq!(r(Expr::bin(BinOp::Xor, x(), x())), "0");
        assert_eq!(r(Expr::bin(BinOp::Shl, x(), Expr::C(0))), "rcx");
        assert_eq!(r(Expr::bin(BinOp::Add, x(), y())), "rcx + rdx");
    }

    #[test]
    fn double_sub_and_add_chain() {
        let x = || Expr::var("rbx");
        let e = Expr::bin(
            BinOp::Sub,
            Expr::bin(BinOp::Add, x(), Expr::C(8)),
            Expr::C(8),
        );
        assert_eq!(r(e), "rbx");
        let e = Expr::bin(
            BinOp::Add,
            Expr::bin(BinOp::Add, x(), Expr::C(4)),
            Expr::C(12),
        );
        assert_eq!(r(e), "rbx + 0x10");
    }

    #[test]
    fn xor_self_involution() {
        let e = Expr::bin(
            BinOp::Xor,
            Expr::bin(BinOp::Xor, Expr::var("rcx"), Expr::var("rdx")),
            Expr::var("rdx"),
        );
        assert_eq!(r(e), "rcx");
    }

    #[test]
    fn nesting_survives_with_parens() {
        let e = Expr::bin(
            BinOp::Add,
            Expr::bin(
                BinOp::Mul,
                Expr::bin(BinOp::Add, Expr::var("rcx"), Expr::var("rdx")),
                Expr::C(2),
            ),
            Expr::C(1),
        );
        assert_eq!(r(e), "((rcx + rdx) << 1) + 1");
    }

    #[test]
    fn precedence_and_associativity() {
        let lhs = || Expr::var("a");
        let e = Expr::bin(
            BinOp::Sub,
            lhs(),
            Expr::bin(BinOp::Sub, Expr::var("b"), Expr::var("c")),
        );
        assert_eq!(r(e), "a - (b - c)");
        let e = Expr::bin(
            BinOp::Sub,
            Expr::bin(BinOp::Sub, Expr::var("a"), Expr::var("b")),
            Expr::var("c"),
        );
        assert_eq!(r(e), "a - b - c");
        let e = Expr::bin(
            BinOp::Add,
            Expr::bin(BinOp::Shl, Expr::var("a"), Expr::C(2)),
            Expr::C(1),
        );
        assert_eq!(r(e), "(a << 2) + 1");
    }

    #[test]
    fn len_bound_is_an_upper_bound_and_saturates() {
        let mut e = Expr::var("rax");
        for _ in 0..10 {
            e = Expr::bin(BinOp::Add, e.clone(), e);
        }
        assert!(e.render().len() <= e.len_bound(usize::MAX));
        let b = e.len_bound(64);
        assert!(b > 64 && b <= 64 + 21, "b={}", b);
        assert!(Expr::bin(BinOp::Add, Expr::var("rcx"), Expr::C(8)).len_bound(1024) < 64);
    }

    #[test]
    fn div_by_zero_stays_symbolic() {
        let e = Expr::bin(BinOp::Div, Expr::var("rax"), Expr::C(0));
        assert_eq!(r(e), "rax / 0");
    }
}
