import base64

msg = b'astraflag{u_r_sUch_An_iS0gen1c_G3niUs!_:p_@Astrageldon}'
enc = base64.b64encode(msg)
flag = b'I am so clever that my isogeny hash is super invulnerable! So my base64-encoded secret "%s" will be non-invertible under this hash function :D' % enc