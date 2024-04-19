import cv2, random, itertools, scipy
import numpy as np

def count(arr):
    ret = [0] * 256
    for i in arr:
        ret[int(i)] += 1
    return ret

def lsb_space_chi2(data0):
    data = data0.copy().flatten()
    bins = count(data)
    chi2 = 0
    for k in range(1,129):
        nexp = (bins[2*k-2]+bins[2*k-1])/2
        if nexp > 1:
            chi2 += (bins[2*k-1]-nexp)**2/nexp
    r = 127
    r2 = 0.5*r
    p = 1 - scipy.integrate.quad(lambda x: x**(r2-1)*np.exp(-0.5*x)/scipy.special.gamma(r2)/2**r2,0,chi2)[0]
    return chi2, p

dst1 = cv2.imread("dst1.png")

h, w, c = dst1.shape
H, W = 128, 128

candidates = []
candidates_capacity = 10

for i in range(0, h, H):
    for j in range(0, w, W):
        p = max(lsb_space_chi2(dst1[i:i+H,j:j+W,c])[1] for c in range(3))
        if len(candidates) >= candidates_capacity:
            candidates = candidates[:-1]
        candidates.append((i, j, p))
        candidates.sort(key = lambda x: -x[-1])

for candidate in candidates:
    print("\t%3d\t%3d\t%10.8f" % candidate)