import cv2, random, itertools, scipy
import numpy as np

src = cv2.imread("src.jpg")

h, w, c = src.shape
H, W = 16, 16

for idx in range(81):
    if random.randint(0,1):
        print(1, end = '')
        i, j = random.randint(0, (h-H+1)//H) * H, random.randint(0, (w-W+1)//W) * W
        sample = (src[i:i+H,j:j+W,:]&1)*255
    else:
        print(0, end = '')
        sample = np.random.randint(0,2,(H,W,c))*255
    cv2.imwrite("task2_samples/%d.png"%(idx+1), sample)

print()