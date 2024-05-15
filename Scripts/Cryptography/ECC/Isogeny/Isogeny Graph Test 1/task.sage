# SageMath 9.3

from secret import flag

pad = lambda s, l: s + bytes(bool(i)*randrange(1,256) for i in range(l-len(s)))
unpad = lambda s: s[:s.index(0)] if 0 in s else s
blocksize = 3

flag = pad(flag, len(flag) + (blocksize - len(flag)) % blocksize)

# Astrageldon's super safe hash function based on the super ultra invincible 2-isogeny map :D
class ECC_Hasher:
    def __init__(self, a, b):
        self.a = a
        self.b = b
        self.l = 2
        self.p = 2**a*3**b-1
        try:
            self.Fp2 = GF(self.p**2, modulus=x**2+1, name='i')
        except AttributeError:
            self.Fp2 = GF(self.p**2, modulus=x**2+1, name='i')
        self.E = EllipticCurve(self.Fp2, [0,6,0,1,0])
        self.E.set_order((self.p+1)**2, num_checks=0)
    def hash(self, msg):
        E = self.E
        last = 1728
        for m in msg:
            cnt = 0
            while cnt < 8:
                t = m & int(0x1)
                roots = E.torsion_polynomial(self.l).roots()
                assert len(roots) == self.l+1 and all(r[1] == 1 for r in roots)
                candidates = [E.isogeny_codomain(E.lift_x(r[0])) for r in roots]
                candidates = [e for e in candidates if e.j_invariant() != last]
                candidates.sort(key = lambda e: e.j_invariant())
                assert len(candidates) == self.l
                last = E.j_invariant()
                E = candidates[t]
                m >>= int(1)
                cnt += 1
        return E.j_invariant()

a = 18
b = 13

hashes = []
Hasher = ECC_Hasher(a, b)
for i in range(0, len(flag), blocksize):
    hashes.append(Hasher.hash(flag[i:i+blocksize]))
print(hashes)
save(hashes, "data")

# [354673685541*i + 47717173229, 304880184212*i + 44627346521, 382382367697*i + 124071050798, 137341268261*i + 88583420867, 24107988773*i + 14845642701, 71447095861*i + 320750136360, 268164027078*i + 365144965522, 306542838330*i + 155537471913, 103764475704*i + 147386060715, 349120448011*i + 127126254103, 328460804768*i + 106100246156, 182400099774*i + 13611555074, 283140909445*i + 143909737304, 296096354358*i + 94538237251, 24107988773*i + 14845642701, 129984303815*i + 46171701633, 67357378398*i + 286388787331, 182489245781*i + 94113723947, 113425783233*i + 76539024791, 292094466482*i + 23313066478, 233174557317*i + 47539744678, 213586011133*i + 89788898817, 74545345943*i + 90610317691, 177694067224*i + 43299097702, 164179630958*i + 18074248873, 62818588614*i + 221672863919, 324458622986*i + 262624850731, 55300397445*i + 87119101489, 385838284390*i + 87076157271, 355184244466*i + 78411023961, 19824641990*i + 33767203253, 6749979994*i + 65166119149, 147209125862*i + 102632722226, 291037405415*i + 143340711723, 89784178163*i + 277079020530, 212063621737*i + 125464532781, 61782171178*i + 52708728430, 209132624365*i + 201647408419, 172741785133*i + 131703882772, 61263655403*i + 207834644610, 35663401340*i + 169988669879, 67805716683*i + 132059714410, 267704379657*i + 29680960960, 118867969240*i + 329750703205, 344156409420*i + 72471518134, 252245735918*i + 83535106509, 233776906081*i + 59361404384, 88977001874*i + 7576068964, 343846784507*i + 198118543797, 60054248717*i + 48953623426, 209587243821*i + 245590978704, 371039192855*i + 358472932934, 389217601571*i + 151656993323, 146790282442*i + 182326391970, 37562883917*i + 360309904217, 151100802954*i + 95899892847, 268432471164*i + 67519123866, 210978054567*i + 160444975759, 275996130810*i + 246502450862, 290698491310*i + 130485353693, 337678952297*i + 29639145225, 179144058498*i + 333668205321, 41389605938*i + 338288967519, 341329757146*i + 14821448128, 24107988773*i + 14845642701, 224728650147*i + 219495079067, 253716556480*i + 151360832815, 193148426850*i + 91643877457, 135997161374*i + 1703829838, 414578930489*i + 47720729050, 308466313352*i + 132704246697, 128360578633*i + 105630497136]