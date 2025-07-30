from flask import Flask, render_template, request

app = Flask(__name__)

# Utility: Left rotate function
def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

# SHA-0 Implementation
def sha0(msg):
    # Preprocessing
    ml = len(msg) * 8
    msg += b'\x80'
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'
    msg += ml.to_bytes(8, 'big')

    # Initialize variables
    h0, h1, h2, h3, h4 = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )

    # Process 512-bit chunks
    for i in range(0, len(msg), 64):
        chunk = msg[i:i+64]
        w = [int.from_bytes(chunk[j:j+4], 'big') for j in range(0, 64, 4)]

        for j in range(16, 80):
            w.append(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16])

        a, b, c, d, e = h0, h1, h2, h3, h4

        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return ''.join(f'{x:08x}' for x in [h0, h1, h2, h3, h4])

# SHA-1 Implementation
def sha1(msg):
    # Preprocessing
    ml = len(msg) * 8
    msg += b'\x80'
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'
    msg += ml.to_bytes(8, 'big')

    # Initialize variables
    h0, h1, h2, h3, h4 = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )

    # Process 512-bit chunks
    for i in range(0, len(msg), 64):
        chunk = msg[i:i+64]
        w = [int.from_bytes(chunk[j:j+4], 'big') for j in range(0, 64, 4)]

        for j in range(16, 80):
            w.append(left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1))  # difference in SHA-1

        a, b, c, d, e = h0, h1, h2, h3, h4

        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return ''.join(f'{x:08x}' for x in [h0, h1, h2, h3, h4])

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    algorithm = None
    if request.method == 'POST':
        text = request.form['text']
        algo = request.form['algo']
        message = text.encode()

        if algo == 'SHA-0':
            result = sha0(message)
            algorithm = 'SHA-0'
        elif algo == 'SHA-1':
            result = sha1(message)
            algorithm = 'SHA-1'

    return render_template('index.html', result=result, algorithm=algorithm)

if __name__ == '__main__':
    app.run(debug=True)
