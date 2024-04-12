import scipy, random, cv2, itertools
import numpy as np

def zigzag_map(v_max, h_max):
    h = 0
    v = 0
    v_min = 0
    h_min = 0
    i = 0
    output = [None] * (v_max * h_max)

    while (v < v_max) and (h < h_max):
        if ((h + v) % 2) == 0:  # going up
            if v == v_min:
                output[i] = (v, h)  # first line
                if h == h_max:
                    v = v + 1
                else:
                    h = h + 1
                i = i + 1
            elif (h == h_max - 1) and (v < v_max):  # last column
                output[i] = (v, h)
                v = v + 1
                i = i + 1
            elif (v > v_min) and (h < h_max - 1):  # all other cases
                output[i] = (v, h)
                v = v - 1
                h = h + 1
                i = i + 1
        else:  # going down
            if (v == v_max - 1) and (h <= h_max - 1):  # last line
                output[i] = (v, h)
                h = h + 1
                i = i + 1
            elif h == h_min:  # first column
                output[i] = (v, h)
                if v == v_max - 1:
                    h = h + 1
                else:
                    v = v + 1
                i = i + 1
            elif (v < v_max - 1) and (h > h_min):  # all other cases
                output[i] = (v, h)
                v = v + 1
                h = h - 1
                i = i + 1
        if (v == v_max - 1) and (h == h_max - 1):  # bottom right element
            output[i] = (v, h)
            break
    return output

def zigzag(matrix):
    """
    computes the zigzag of a quantized block
    :param numpy.ndarray matrix: quantized matrix
    :returns: zigzag vectors in an array
    """
    # initializing the variables
    h = 0
    v = 0
    v_min = 0
    h_min = 0
    v_max = matrix.shape[0]
    h_max = matrix.shape[1]
    i = 0
    output = np.zeros((v_max * h_max)).astype(matrix.dtype)

    while (v < v_max) and (h < h_max):
        if ((h + v) % 2) == 0:  # going up
            if v == v_min:
                output[i] = matrix[v, h]  # first line
                if h == h_max:
                    v = v + 1
                else:
                    h = h + 1
                i = i + 1
            elif (h == h_max - 1) and (v < v_max):  # last column
                output[i] = matrix[v, h]
                v = v + 1
                i = i + 1
            elif (v > v_min) and (h < h_max - 1):  # all other cases
                output[i] = matrix[v, h]
                v = v - 1
                h = h + 1
                i = i + 1
        else:  # going down
            if (v == v_max - 1) and (h <= h_max - 1):  # last line
                output[i] = matrix[v, h]
                h = h + 1
                i = i + 1
            elif h == h_min:  # first column
                output[i] = matrix[v, h]
                if v == v_max - 1:
                    h = h + 1
                else:
                    v = v + 1
                i = i + 1
            elif (v < v_max - 1) and (h > h_min):  # all other cases
                output[i] = matrix[v, h]
                v = v + 1
                h = h - 1
                i = i + 1
        if (v == v_max - 1) and (h == h_max - 1):  # bottom right element
            output[i] = matrix[v, h]
            break
    return output

def count(arr):
    ret = [0] * 256
    for i in arr:
        ret[int(i)] += 1
    return ret

def lsb_space_random(img0):
    img = img0.copy()
    for indices in itertools.product(*[range(s) for s in img.shape]):
        img[indices] &= 0xfe
        img[indices] |= random.randint(0,1)
    return img

def lsb_freq_random(img0, QF = 50):
    assert img0.shape == (8, 8)
    img = img0.copy().astype('float') - 128
    Q0 = np.array([
        [16, 11, 10, 16, 24, 40, 51, 61],
        [12, 12, 14, 19, 26, 58, 60, 55],
        [14, 13, 16, 24, 40, 57, 69, 56],
        [14, 17, 22, 29, 51, 87, 80, 62],
        [18, 22, 37, 56, 68, 109, 103, 77],
        [24, 35, 55, 64, 81, 104, 113, 92],
        [49, 64, 78, 87, 103, 121, 120, 101],
        [72, 92, 95, 98, 112, 100, 103, 99]
    ])
    T = cv2.dct(img)
    if QF < 50:
        Q = np.floor(50/QF*Q0+1/2)
    elif 50 <= QF < 100:
        Q = np.floor((2-QF/50)*Q0+1/2)
        for i,j in itertools.product(*[range(s) for s in Q.shape]):
            Q[i,j] = max(Q[i,j], 1)
    T /= Q
    T = np.round(T).astype(int)
    zz = zigzag_map(*img.shape)
    maxi = len(zz) - 1
    while T[zz[maxi]] == 0:
        maxi -= 1
    #print(T, maxi)
    for i,j in enumerate(zz):
        if i > 0 and i <= maxi and T[j] not in [0,-1,1]:
            s = np.sign(T[j])
            T[j] = abs(T[j]) & 0xfe
            T[j] |= random.randint(0,1)
            T[j] *= s
    #print(T)
    T_ = np.round(cv2.idct((T*Q).astype('float'))).astype(int)+128
    for i,j in itertools.product(*[range(s) for s in T_.shape]):
        T_[i,j] = max(min(T_[i,j], 255), 0)
    return T_
       

def lsb_space_chi2(data0):
    # https://www.cl.cam.ac.uk/teaching/0910/R08/work/essay-at443-steganography.pdf
    data = data0.flatten()
    bins = count(data)
    chi2 = 0
    for k in range(1,128):
        nexp = (bins[2*k-2]+bins[2*k-1])/2
        if nexp > 5:
            chi2 += (bins[2*k-1]-nexp)**2/nexp
    r = 127
    r2 = 0.5*r
    p = 1 - scipy.integrate.quad(lambda x: x**(r2-1)*np.exp(-0.5*x)/scipy.special.gamma(r2)/2**r2,0,chi2)[0]
    return chi2, p

'''
def lsb_freq_chi2(data0, QF = 90):
    assert data0.shape == (8, 8)
    Q0 = np.array([
        [16, 11, 10, 16, 24, 40, 51, 61],
        [12, 12, 14, 19, 26, 58, 60, 55],
        [14, 13, 16, 24, 40, 57, 69, 56],
        [14, 17, 22, 29, 51, 87, 80, 62],
        [18, 22, 37, 56, 68, 109, 103, 77],
        [24, 35, 55, 64, 81, 104, 113, 92],
        [49, 64, 78, 87, 103, 121, 120, 101],
        [72, 92, 95, 98, 112, 100, 103, 99]
    ])
    T = cv2.dct(data0.astype(float))
    if QF < 50:
        Q = np.floor(50/QF*Q0+1/2)
    elif 50 <= QF < 100:
        Q = np.floor((2-QF/50)*Q0+1/2)
        for i,j in itertools.product(*[range(s) for s in Q.shape]):
            Q[i,j] = max(Q[i,j], 1)
    T /= Q
    T = np.round(T).astype(int)
    return lsb_space_chi2(T)
'''