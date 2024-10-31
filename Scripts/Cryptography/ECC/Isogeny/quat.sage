#!/usr/bin/env sage
#coding: utf8

'''
This is a rough proof-of-concept implementation accompanying
the paper "Rational isogenies from irrational endomorphisms".
ePrint URL: https://ia.cr/2019/1202
Last update of this file: 2020-03-08
'''

p = 419
p = 12011
p = 995337419

maximal = True

########################################

## find a representation for B_p,∞

q = 1
while True:
    Quat.<i,j,k> = QuaternionAlgebra(-q,-p)
    if Quat.discriminant() == p: break
    q += 1

########################################

## algorithms

el2vec = lambda a: list(Quat(a))
vec2el = lambda v: sum(x*y for x,y in zip(v, Quat.basis()))

# return a matrix whose row span is the intersection of two matrices' row spans
def intersect(L0, L1):
    return L0.row_module(ZZ).intersection(L1.row_module(ZZ)).basis_matrix()

# find a small "twisting endomorphism" in a given quaternion order
def twistendo(Q):
    M = Q.unit_ideal().basis_matrix()
    L = intersect(M, matrix(map(el2vec, [i,k])))  # compute <i,k> submodule
    S = diagonal_matrix([round(1e9*sqrt(g.reduced_norm())) for g in Quat.basis()])
    L = (L * S).LLL() * S**-1                     # find small-norm element
    return vec2el(L.rows()[0])

# intersect a quaternion O-ideal with O = Q ∩ ℚ(j)
def fpify(I):
    P = matrix(identity_matrix(4).rows()[::-1])
    M = I.basis_matrix()
    S = matrix(map(list, O.basis())) * matrix([[1,0,0,0],[0,0,1,0]])    # the <1,j> part of O
    L = intersect(M*P, S*P) * P
    ret = [sum(x*g for x,g in zip(r, [1,0,pi,0])) for r in L.rows()]    # convert to K-elements
    return ret[::-1] if ret[0] not in ZZ else ret

########################################

## generate a test instance

from sage.algebras.quatalg.quaternion_algebra import basis_for_quaternion_lattice
bfql = lambda L: basis_for_quaternion_lattice(L, reverse=True)

#Q0 = Quat.quaternion_order([1, i, (1+j)/2, (i+k)/2])   # y^2 = x^3 - x, only p = 3 mod 4
Q0 = Quat.maximal_order()

K.<pi> = QuadraticField(-p)
if maximal:
    O = K.maximal_order()
else:
    O = K.order(pi)
    O.ideal(1)  # throws NotImplemented as of March 2020

# walk around the isogeny graph to find a "random" maximal order
Q1 = Q0
orig = O.ideal(1)
for step in range(40):
    while True:
        l = random_prime(1000, lbound=3)
        if not Mod(-p,l).is_square(): continue  # check if Elkies
        break
    mu = ZZ(sqrt(Mod(-p,l)))
    orig *= K.ideal((l, pi-mu))
    # corresponds to quotienting by the mu-eigenspace of Frobenius
    IK = Quat.ideal(bfql(
            Q1.unit_ideal().scale(l).basis()
          + Q1.unit_ideal().scale(j-mu).basis())
        )
    Q1 = IK.right_order()

########################################

## check that the algorithms solve the test instance

from sage.rings.factorint import factor_trial_division
def tryfactor(n):
    if n in ZZ: return factor_trial_division(n, 1e8)
    return tryfactor(n.numerator()) / tryfactor(n.denominator())

print()
print('p = {}'.format(p))
print()

print('Q₀:')
for g in Q0.basis():
    print('  {}'.format(g))
print()

print('Q₁:')
for g in Q1.basis():
    print('  {}'.format(g))
print()

beta = twistendo(Q0)
print('\x1b[33mβ = {}\x1b[0m'.format(beta))
print('norm(β) = {}'.format(tryfactor(beta.reduced_norm())))
assert beta*j == -j*beta
print()

gamma = twistendo(Q1)
print('\x1b[33mγ = {}\x1b[0m'.format(gamma))
print('norm(γ) = {}'.format(tryfactor(gamma.reduced_norm())))
assert gamma*j == -j*gamma
print

I = Q0.unit_ideal().scale(beta)
print('I = Q₀·β:')
for g in I.basis():
    print('  {}'.format(g))
print()

J = Q1.unit_ideal().scale(gamma)
print('J = Q₁·γ:')
for g in J.basis():
    print('  {}'.format(g))
print()

bb = O.ideal(fpify(I))
print('\x1b[36mbb = I ∩ O = <{}>\x1b[0m'.format(bb.gens_two()))
print('norm(bb) = {}'.format(tryfactor(bb.norm())))
print('norm(bb)/norm(I) = {}'.format(tryfactor(bb.norm() / I.norm())))
print()

cc = O.ideal(fpify(J))
print('\x1b[36mcc = J ∩ O = <{}>\x1b[0m'.format(cc.gens_two()))
print('norm(cc) = {}'.format(tryfactor(cc.norm())))
print('norm(cc)/norm(J) = {}'.format(tryfactor(cc.norm() / J.norm())))
print()

aa2 = bb/cc
print('--> \x1b[32m[aa]^2 = [bb/cc] = [<{}>]\x1b[0m'.format(aa2.gens_two()))
print()

print('actual square of connecting ideal: <{}>'.format((orig**2).gens_two()))
print('equivalent? \x1b[31m{}\x1b[0m'.format((aa2 / orig**2).is_principal()))
print()

