import os
import sys
import io
import zipfile
from flask import Flask, request, redirect, url_for, send_file, render_template, send_from_directory
from werkzeug.utils import secure_filename
from hashlib import sha1
from PIL import Image
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b



UPLOAD_FOLDER = '/path/to/the/uploads'
ALLOWED_EXTENSIONS = set(['jpg', 'jpeg'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def jpeg_comment(n):
    # Comment size can be only setted in 2 bytes
    assert n < 0xffff, "Oversized image data (up to 65535 bytes)."
    n += 2
    return '\xff\xfe' + l2b(n>>8) + l2b(n & 0xff)

def generate_collision(file1, file2):

    img1 = file1
    img2 = file2
    
    # Check JPEG format
    if b2l(img1[:2]) != 0xffd8 or b2l(img2[:2]) != 0xffd8:
        print "Image is not JPEG format."
        sys.exit(1)

    size1 = Image.open(io.BytesIO(img1)).size
    size2 = Image.open(io.BytesIO(img2)).size
    print "Image size:", size1

    # Resize the image if different sizes
    if size1 != size2:
        tmpIO = io.BytesIO()
        new = Image.open(io.BytesIO(img2)).resize(size1)
        new.save(tmpIO, format= 'JPEG')
        img2 = tmpIO.getvalue()
        print "Resized:", "file2"


    pdf_header = l2b(0x255044462D312E330A25E2E3CFD30A0A0A312030206F626A0A3C3C2F57696474682032203020522F4865696768742033203020522F547970652034203020522F537562747970652035203020522F46696C7465722036203020522F436F6C6F7253706163652037203020522F4C656E6774682038203020522F42697473506572436F6D706F6E656E7420383E3E0A73747265616D0A)
    jpg_header = l2b(0xFFD8FFFE00245348412D3120697320646561642121212121852FEC092339759C39B1A1C63C4C97E1FFFE01)

    # Collision blocks (This is the only part of the files which is different)
    collision_block1 = l2b(0x7F46DC93A6B67E013B029AAA1DB2560B45CA67D688C7F84B8C4C791FE02B3DF614F86DB1690901C56B45C1530AFEDFB76038E972722FE7AD728F0E4904E046C230570FE9D41398ABE12EF5BC942BE33542A4802D98B5D70F2A332EC37FAC3514E74DDC0F2CC1A874CD0C78305A21566461309789606BD0BF3F98CDA8044629A1)
    collision_block2 = l2b(0x7346DC9166B67E118F029AB621B2560FF9CA67CCA8C7F85BA84C79030C2B3DE218F86DB3A90901D5DF45C14F26FEDFB3DC38E96AC22FE7BD728F0E45BCE046D23C570FEB141398BB552EF5A0A82BE331FEA48037B8B5D71F0E332EDF93AC3500EB4DDC0DECC1A864790C782C76215660DD309791D06BD0AF3F98CDA4BC4629B1)

    prefix1 = pdf_header + jpg_header + collision_block1
    prefix2 = pdf_header + jpg_header + collision_block2


    data = ''
    data += b'\x00' * 242
    data += jpeg_comment(8 + len(img1[2:]))
    data += b'\x00' * 8
    data += img1[2:]
    data += img2[2:]
    data += b'endstream\nendobj\n\n'

    # Cross-reference Table
    xref = b'xref\n'
    xref += b'0 13 \n'
    xref += b'0000000000 65535 f \n'
    xref += b'0000000017 00000 n \n'

    xref += b'%010d 00000 n \n' % len(prefix1+data)
    # width
    data += b'2 0 obj\n%010d\nendobj\n\n' % size1[0]
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    # height
    data += b'3 0 obj\n%010d\nendobj\n\n' % size1[1]
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    data += b'4 0 obj\n/XObject\nendobj\n\n'
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    data += b'5 0 obj\n/Image\nendobj\n\n'
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    data += b'6 0 obj\n/DCTDecode\nendobj\n\n'
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    data += b'7 0 obj\n/DeviceRGB\nendobj\n\n'
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    # JPEG size
    data += b'8 0 obj\n%010d\nendobj\n\n' % len(img1+img2)
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    data += b'9 0 obj\n<<\n  /Type /Catalog\n  /Pages 10 0 R\n>>\nendobj\n\n'
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    data += b'10 0 obj\n<<\n  /Type /Pages\n  /Count 1\n  /Kids [11 0 R]\n>>\nendobj\n\n'
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    data += b'11 0 obj\n<<\n  /Type /Page\n  /Parent 10 0 R\n  /MediaBox [0 0 %010d %010d]\n  /CropBox [0 0 %010d %010d]\n  /Contents 12 0 R\n  /Resources\n  <<\n    /XObject <</Im0 1 0 R>>\n  >>\n>>\nendobj\n\n' % (size1[0], size1[1], size1[0], size1[1])
    xref += b'%010d 00000 n \n' % len(prefix1+data)
    data += b'12 0 obj\n<</Length 49>>\nstream\nq\n  %010d 0 0 %010d 0 0 cm\n  /Im0 Do\nQ\nendstream\nendobj\n\n' % (size1[0], size1[1])

    xref_pos = len(prefix1 + data)
    data += xref
    trailer = b'\ntrailer << /Root 9 0 R /Size 13>>\n\nstartxref\n%010d\n%%%%EOF\n' % xref_pos

    data += trailer

    outfile1 = prefix1 + data
    outfile2 = prefix2 + data
    
    # Check SHA-1 collision
    assert sha1(outfile1).hexdigest() == sha1(outfile2).hexdigest()

    print "Successfully Generated Collision PDF !!!"
    
    return outfile1, outfile2



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_size(fobj):
    if fobj.content_length:
        return fobj.content_length

    try:
        pos = fobj.tell()
        fobj.seek(0, 2)  #seek to end
        size = fobj.tell()
        fobj.seek(pos)  # back to original position
        return size
    except (AttributeError, IOError):
        pass

    # in-memory file object that doesn't support seeking or tell
    return 0  #assume small enough

def check_valid_file(fileinp):
    if fileinp.filename == '':
        return False
    if fileinp and allowed_file(fileinp.filename) and get_size(fileinp) < 65536:
        return True
    return False

@app.route('/assets/<path:path>')
def send_js(path):
    return send_from_directory('assets', path)


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file1' not in request.files or 'file2' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file1 = request.files['file1']
        file2 = request.files['file2']

        if check_valid_file(file1) and check_valid_file(file2):
            col1, col2 = generate_collision(file1.read(), file2.read())
            data = io.BytesIO()
            with zipfile.ZipFile(data, mode='w') as z:
                z.writestr('file1-collision.pdf', col1)
                z.writestr('file2-collision.pdf', col2)
            data.seek(0)
            return send_file(data, mimetype='application/zip',
                            as_attachment=True,
                            attachment_filename='collision.zip')

        flash("wrong file type")

    return '''
    <!doctype html>
    <head>
        <title>SHA-1 Collider by Nooberpool</title>
        <link rel="stylesheet" type="text/css" href="/assets/semantic.min.css">
        <script src="/assets/jquery-3.1.1.min.js"></script>
        <script src="/assets/semantic.min.js"></script>
  <style type="text/css">
    body {
      background-color: #DADADA;
    }
    body > .grid {
      height: 100%;
    }
    .image {
      margin-top: -100px;
    }
    .column {
      max-width: 450px;
    }
  </style>
    </head>
    <body>

        <div class="ui middle aligned center aligned grid">
          <div class="column">
            <h2 class="ui teal image header">
              <div class="content">
                SHA-1 Collider by Nooberpool
              </div>
            </h2>
            <form class="ui large form" method="post" enctype="multipart/form-data">
              <div class="ui stacked segment">
                <div class="field">
                    <label>File 1:</label>
                    <input type="file" name="file1" accept="jpg, jpeg">
                </div>
                <div class="field">
                    <label> File 2: </label>
                    <input type="file" name="file2" accept="jpg, jpeg">
                </div>
                <button type="submit"  class="ui fluid large teal submit button">Upload!</div>
              </div>
            </form>
          </div>
        </div>
    </body>
    '''
