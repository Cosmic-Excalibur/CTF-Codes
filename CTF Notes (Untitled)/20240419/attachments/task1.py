import cv2, random, itertools
import numpy as np

def lsb_space_random(src):
    img = src.copy()
    img &= 0xfe
    return img | np.random.randint(0,2,img.shape)

src = cv2.imread("src.jpg")

h, w, c = src.shape

H, W = 128, 128

i, j = random.randint(0, (h-H+1)//H) * H, random.randint(0, (w-W+1)//W) * W
dst1 = src.copy()
dst1[i:i+H,j:j+W] = lsb_space_random(src[i:i+H,j:j+W])

print(i, i+H, j, j+W)
cv2.imwrite("dst1.png", dst1)
cv2.imwrite("src_lsb.png", (src[:,:,:]&1)*255)
cv2.imwrite("dst1_lsb.png", (dst1[:,:,:]&1)*255)
cv2.imwrite("src_block1_lsb.png", (src[i:i+H,j:j+H,:]&1)*255)
cv2.imwrite("dst1_block1_lsb.png", (dst1[i:i+H,j:j+H,:]&1)*255)
cv2.imwrite("src_random_lsb.png", (lsb_space_random(src[:,:,:])&1)*255)