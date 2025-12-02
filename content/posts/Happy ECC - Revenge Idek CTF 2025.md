---
title: Happy ECC - Revenge Idek CTF 2025
date: 2025-08-04
draft: false
tags:
  - idek-ctf
  - ECC
  - hyperelliptic-curve
---
During the weekend, I participated in Idek CTF, which was a nice CTF. I was able to solve a cryptography challenge about hyperelliptic curves, which is something new to me.
![Image Description](/images/Pasted%20image%2020250805121656.png)

# Code analysis

```python
from sage.all import *
from Crypto.Util.number import *

# Edited a bit from <https://github.com/aszepieniec/hyperelliptic/blob/master/hyperelliptic.sage>
class HyperellipticCurveElement:
    def __init__( self, curve, U, V ):
        self.curve = curve
        self.U = U
        self.V = V

    @staticmethod
    def Cantor( curve, U1, V1, U2, V2 ):
        # 1.
        g, a, b = xgcd(U1, U2)   # a*U1 + b*U2 == g
        d, c, h3 = xgcd(g, V1+V2) # c*g + h3*(V1+V2) = d
        h2 = c*b
        h1 = c*a
        # h1 * U1 + h2 * U2 + h3 * (V1+V2) = d = gcd(U1, U2, V1-V2)

        # 2.
        V0 = (U1 * V2 * h1 + U2 * V1 * h2 + (V1*V2 + curve.f) * h3).quo_rem(d)[0]
        R = U1.parent()
        V0 = R(V0)

        # 3.
        U = (U1 * U2).quo_rem(d**2)[0]
        U = R(U)
        V = V0 % U

        while U.degree() > curve.genus:
            # 4.
            U_ = (curve.f - V**2).quo_rem(U)[0]
            U_ = R(U_)
            V_ = (-V).quo_rem(U_)[1]

            # 5.
            U, V = U_.monic(), V_
        # (6.)

        # 7.
        return U, V

    def parent( self ):
        return self.curve

    def __add__( self, other ):
        U, V = HyperellipticCurveElement.Cantor(self.curve, self.U, self.V, other.U, other.V)
        return HyperellipticCurveElement(self.curve, U, V)

    def inverse( self ):
        return HyperellipticCurveElement(self.curve, self.U, -self.V)

    def __rmul__(self, exp):
        R = self.U.parent()
        I = HyperellipticCurveElement(self.curve, R(1), R(0))

        if exp == 0:
            return HyperellipticCurveElement(self.curve, R(1), R(0))
        if exp == 1:
            return self

        acc = I
        Q = self
        while exp:
            if exp & 1:
                acc = acc + Q
            Q = Q + Q
            exp >>= 1
        return acc

    def __eq__( self, other ):
        if self.curve == other.curve and self.V == other.V and self.U == other.U:
            return True
        else:
            return False

class HyperellipticCurve_:
    def __init__( self, f ):
        self.R = f.parent()
        self.F = self.R.base_ring()
        self.x = self.R.gen()
        self.f = f
        self.genus = floor((f.degree()-1) / 2)

    def identity( self ):
        return HyperellipticCurveElement(self, self.R(1), self.R(0))

    def random_element( self ):
        roots = []
        while len(roots) != self.genus:
            xi = self.F.random_element()
            yi2 = self.f(xi)
            if not yi2.is_square():
                continue
            roots.append(xi)
            roots = list(set(roots))
        signs = [ZZ(Integers(2).random_element()) for r in roots]

        U = self.R(1)
        for r in roots:
            U = U * (self.x - r)

        V = self.R(0)
        for i in range(len(roots)):
            y = (-1)**(ZZ(Integers(2).random_element())) * sqrt(self.f(roots[i]))
            lagrange = self.R(1)
            for j in range(len(roots)):
                if j == i:
                    continue
                lagrange = lagrange * (self.x - roots[j])/(roots[i] - roots[j])
            V += y * lagrange

        return HyperellipticCurveElement(self, U, V)

p = getPrime(40)
R, x = PolynomialRing(GF(p), 'x').objgen()

f = R.random_element(5).monic()
H = HyperellipticCurve_(f)

print(f"{p = }")
if __name__ == "__main__":
    cnt = 0
    while True:
        print("1. Get random point\\n2. Solve the challenge\\n3. Exit")
        try:
            opt = int(input("> "))
        except:
            print("❓ Try again."); continue

        if opt == 1:
            if cnt < 3:
                G = H.random_element()
                k = getRandomRange(1, p)
                P = k * G
                print("Here is your point:")
                print(f"{P.U = }")
                print(f"{P.V = }")
                cnt += 1
            else:
                print("You have enough point!")
                continue

        elif opt == 2:
            G = H.random_element()
            print(f"{(G.U, G.V) = }")
            print("Give me the order !")
            odr = int(input(">"))
            if (odr * G).U == 1 and odr > 0:
                print("Congratz! " + open("flag.txt", "r").read())
            else:
                print("Wrong...")
            break

        else:
            print("Farewell.")
```

The code looks huge, but `HyperellipticCurve_` and `HyperellipticCurveElement` Classes will not affect our approach, so let’s explain each important part of the code:

```python
p = getPrime(40)
R, x = PolynomialRing(GF(p), 'x').objgen()
f = R.random_element(5).monic()
H = HyperellipticCurve_(f)
```

The code starts by generating a 40-bit prime number and building the field $F_p$. Then it chooses a random polynomial whose degree is $\leq 5$. Finally, it defines the Hyperelliptic Curve using the polynomial.

## Some fundamentals on hyper-elliptic curves

What is a hyperelliptic curve?. Think of it as a normal elliptic curve, but with this formula

$$ C: y^2=f(x) $$

You may ask yourself what the difference is between the ordinary elliptic curve and the hyper-elliptic curve. An ordinary elliptic curve $f$ is cubic (degree 3). In our challenge, it is quintic (degree 5).

### Genus

For an equation $y^2=f(x)$ the genus is

$$ \begin{equation*} g = \left\lfloor \frac{\deg f - 1}{2} \right\rfloor. \end{equation*} $$

- **Degree 3** $\Rightarrow g =1 \rightarrow \text{elliptic curve}$
- **Degree 5 $\Rightarrow g =2 \rightarrow \text{a genus-2 hyperelliptic curve}$**

Geometrically, the genus counts the number of “holes” in the curve’s Riemann surface. Algebraically, it tells you how complicated the group law will be. When $g=1$ a single point and its reflection are enough. When $g=2$ a line meets the curve in 5 points so applying the normal method that we would normally apply on an elliptic curve will not work because we will have many points to choose from. To overcome this, we switch from single points to tiny pairs of points called divisors, and those pairs form a tidy abelian group known as the Jacobian of the curve. Roughly speaking, two points determine a line, and plugging that line into$y^2=f(x)$ gives another intersection, which we fold back to keep degrees small; this is called [Cantor’s algorithm](https://people.cs.nycu.edu.tw/~rjchen/ECC2012S/Elliptic%20Curves%20Number%20Theory%20And%20Cryptography%202n.pdf) (Chapter 13.3 for more details). Every divisor can be written as a pair of short polynomials $(U,V)$ with $\text{deg}\ U \leq 2 \ \text{and}\ \text{deg} \ V \lt \text{deg} \ U$ .

## Back to the challenge

```python
if opt == 1:
            if cnt < 3:
                G = H.random_element()
                k = getRandomRange(1, p)
                P = k * G
                print("Here is your point:")
                print(f"{P.U = }")
                print(f"{P.V = }")
                cnt += 1
            else:
                print("You have enough point!")
                continue

```

Option 1 will return to you a Jacobian element, but what lives inside a Jacobian element?. For a hyper-elliptic curve of form

$$ C: y^2=f(x) \ \text{where f is a monic degree-5 polynomial over} \ \mathbb F_p $$

any point in the Jacobian is stored in Mumford form as a pair of small polynomials

$$ (U(x),V(x)) $$

```python
elif opt == 2:
            G = H.random_element()
            print(f"{(G.U, G.V) = }")
            print("Give me the order !")
            odr = int(input(">"))
            if (odr * G).U == 1 and odr > 0:
                print("Congratz! " + open("flag.txt", "r").read())
            else:
                print("Wrong...")
            break
```

Option 2 will choose a random divisor $G$ in the same Jacobian of the same curve. In Mumford form. And asks us to provide the smallest positive integer $n$ such that $nG= 1$. In other words, they need the order of the Jacobian group.

# Solve

To get the order of the element in the Jacobian group, we need to have the real polynomial first. And to have the polynomial, we need to have some of the curve points to do something like [Lagrange interpolation](https://www.youtube.com/watch?v=1pQJkt7-R4Q&t=32s&ab_channel=vcubingx) _(6:12)_. But how are we gonna get the points?

## Part 1, let’s leak some points

Remember that option 1 returns a pair of small polynomials

$$ (U(x),V(x)) $$

And these 2 polynomials should follow the following rules

1. $U$ is monic and $\text{deg} \ U \leq 2$.
2. $\text{deg} \ V < \text{deg} \ U$ So V is at most linear.
3. $U$ divides $V^2-f, \text{written} \ U \ | \ (V^2-f).$

Because $\text{deg} \ U \leq 2$ the usual case is $\text{deg} \ U = 2$, then $U$ factors into

$$ U(x)=(x-x_1)(x-x_2). $$

congrats, you have the 2 roots $x_1, \text{and} \ x_2$. Now rule #3 means that there exists another polynomial $Q(x)$ such that

$$ V(x)^2-f(x)=Q(x)U(x) $$

let’s use any root, like $x_1$

$$ \begin{gather} V(x_1)^2 - f(x_1) = \underbrace{Q(x_1)\,U(x_1)}_{=0},\\ V(x_1)^2 - f(x_1) = 0,\\ V(x_1)^2 = f(x_1). \end{gather} $$

after you leak 6 points, using this, you will be able to reconstruct the curve, then get the order.

## Part 2, Order Order Orderrrr

```python
C = HyperellipticCurve(f)
Z = C.zeta_function()        # returns P(T)/(1-T)(1-pT)
P = Z.numerator()            # grab P(T)
N = ZZ(P(1))                 # |J(𝔽ₚ)|
```

These 4 lines are all that you need to get the order, let me explain.

### What “zeta function” mean

For every extension field $F_{p^n}$ you could count the number of points on the curve

$$\begin{align*} N_1 &= \#C\bigl(\mathbb{F}_p\bigr),\\ N_2&=\#C\bigl(\mathbb{F}_{p^2}\bigr),\\ N_3 &= \#C\bigl(\mathbb{F}_{p^3}\bigr),\\ &\vdots \\ \end{align*}$$

Which is an infinite list of integers. Zeta function stores them all at once like this

$$ \begin{equation*} Z_C(T) = \exp\Bigl(\sum_{n=1}^{\infty}\frac{N_n}{n}T^n\Bigr).\end{equation*} $$

But for any smooth curve of genus $g$, this infinite series can be reduced to

$$ \begin{equation*}Z_C(T) = \frac{P(T)}{(1 - T)\,(1 - pT)}.\end{equation*} $$

where $P(T)$ is a polynomial of degree $2g$ and remember that our curve’s genus is 2, so $P(T)$ is degree 4:

$$ \begin{equation*}P(T) = 1 + a_1 T + a_2 T^2 + a_1 p T^3 + p^2 T^4.\end{equation*}$$

The polynomial $P(T)$ is the characteristic polynomial of the Frobenius endomorphism acting on the Jacobian of the curve. And by definition, the eigenvalues of that Frobenius action are the roots of $P$. So for genus 2

$$ \begin{equation*}P(T) \;=\; \prod_{i=1}^4 \bigl(1 -\alpha_iT\bigr).\end{equation*} $$

and we have that the order of the Jacobian is something like

$$ \begin{equation*}\lvert J(\mathbb{F}_p)\rvert= \prod_{i=1}^{4}\bigl(1 - \alpha_i\bigr).\end{equation*} $$

*Tbh, explaining this will be too much math (already had enough HAHAHAHA).*Any way we can notice that

$$ \lvert J(\mathbb{F}_p) \rvert = P(1) $$

```python
N = ZZ(P(1))              
```

Congrats, send this number to the server, and you will have the flag ready for you. The solver takes about 9 minutes on my potato laptop.

# Final solver script

This was a great challenge that allowed me to learn a lot of new concepts. Kudos @giappppp for the amazing challenge. and see you later （づ￣3￣）づ╭❤️～
```python
from os import environ
environ['TERM'] = 'kitty'
from sage.all import *
from pwn import *
import re, sys

io   = remote("happy-ecc-revenge.chal.idek.team", 1337)

from pow import *
from pow import solve_challenge
line  = io.recvuntil(b'Solution? ')
token = re.search(rb"solve (s\.[^\s]+)", line).group(1).decode()
io.sendline(solve_challenge(token).encode())
io.recvuntil(b'Correct\n')
p   = int(io.recvline().decode().split('=')[1])
print(f"[+] prime p = {p}")
R.<x> = PolynomialRing(GF(p))
def menu(c):          
    io.sendline(str(c).encode())
roots, vals = [], []
for i in range(3):                  
    menu(1)                      
    io.recvuntil(b"P.U = "); U = R(io.readline().strip().decode())
    io.recvuntil(b"P.V = "); V = R(io.readline().strip().decode())
    print(f"[DEBUG] Point {i+1}: U = {U}, factorization = {U.factor()}")
    for fac, _ in U.factor():          
        if fac.degree() == 1:
            r = (-fac[0]) / fac[1]      
            if r not in roots:
                roots.append(r)
                vals.append((V(r) ** 2))
                print(f"[DEBUG] Added root {r} with value {V(r) ** 2}")

print(f"[+] roots after menu-1: {len(roots)}")
menu(2)                            
io.recvuntil(b"(G.U, G.V) = (")
raw = io.readline().decode().rstrip(")\n")
U_str, V_str = map(str.strip, raw.split(", ", 1))
U_G, V_G = R(U_str), R(V_str)

print(f"[DEBUG] Challenge point: U_G = {U_G}, factorization = {U_G.factor()}")
for fac, _ in U_G.factor():
    if fac.degree() == 1:
        r = (-fac[0]) / fac[1]
        if r not in roots:
            roots.append(r)
            vals.append((V_G(r) ** 2))
            print(f"[DEBUG] Added challenge root {r} with value {V_G(r) ** 2}")

print(f"[+] total distinct roots: {len(roots)}")
print(f"[INFO] We have {len(roots)} evaluations, need 6 for full reconstruction")
if len(roots) < 6:

    print("[INFO] Insufficient points for full Lagrange interpolation(just re run the solver)")

    exit()
else:
    f = R.lagrange_polynomial(list(zip(roots[:6], vals[:6]))).monic()
    print(f"[+] recovered f(x) = {f} (degree {f.degree()})")

C = HyperellipticCurve(f)            
Z = C.zeta_function()              
P = Z.numerator()                    
N = ZZ(P(1))                        
print(f"[+] |J(F_p)| = {N}")
io.sendlineafter(b"Give me the order !\n>", str(N).encode())
print(io.recvline().decode().strip())
```

