import cv2, random, itertools, scipy
import numpy as np
from statsmodels.sandbox.stats.runs import runstest_1samp

dst1 = cv2.imread("dst1.png")

h, w, c = dst1.shape
H, W = 128, 128

candidates = []
candidates_capacity = 10

for i in range(0, h, H):
    for j in range(0, w, W):
        p = max(runstest_1samp(dst1[i:i+H,j:j+W,c].flatten()&1)[1] for c in range(3))
        if len(candidates) >= candidates_capacity:
            candidates = candidates[:-1]
        candidates.append((i, j, p))
        candidates.sort(key = lambda x: -x[-1])

for candidate in candidates:
    print("\t%3d\t%3d\t%10.8f" % candidate)