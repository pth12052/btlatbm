from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from crypto_utils import *
import time

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Lưu trữ tạm bộ nhớ
users = {}      # username -> {password, rsa_keys, peer_rsa, des3_key}
messages = []   # danh sách tin nhắn

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            session['user'] = username
            return redirect(url_for('chat'))
        return render_template('login.html', error="Đăng nhập thất bại!")
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return render_template('register.html', error="Tên người dùng đã tồn tại!")
        rsa_keys = generate_rsa_keys()
        users[username] = {
            'password': password,
            'rsa': rsa_keys,  # (private_key, public_key)
            'peer_rsa': None,
            'des3_key': None
        }
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user' not in session:
        return redirect('/')

    current_user = session['user']
    if request.method == 'POST':
        receiver = request.form['receiver']
        message = request.form['message']

        if receiver not in users:
            return "Người nhận không tồn tại."

        # Nếu chưa trao khóa, thực hiện trao khóa
        if not users[current_user]['des3_key']:
            des3_key = DES3.adjust_key_parity(get_random_bytes(24))
            users[current_user]['des3_key'] = des3_key

            peer_pubkey = users[receiver]['rsa'][1]
            encrypted_key = rsa_encrypt(peer_pubkey, des3_key)
            auth_info = f"{current_user}|{int(time.time())}"
            signed_info = sign_data(users[current_user]['rsa'][0], auth_info)

            messages.append({
                'from': current_user,
                'to': receiver,
                'type': 'key_exchange',
                'encrypted_3des_key': encrypted_key,
                'signed_info': signed_info,
                'auth_info': auth_info
            })
            return redirect('/chat')

        # Mã hóa và gửi tin nhắn
        iv, cipher_text = triple_des_encrypt(users[current_user]['des3_key'], message)
        hash_value = sha256_hash(iv, cipher_text)
        signed_hash = sign_data(users[current_user]['rsa'][0], hash_value)

        messages.append({
            'from': current_user,
            'to': receiver,
            'type': 'message',
            'iv': iv,
            'cipher': cipher_text,
            'hash': hash_value,
            'sig': signed_hash
        })
        return redirect('/chat')

    inbox = [msg for msg in messages if msg['to'] == current_user]
    return render_template('chat.html', users=users, current_user=current_user, inbox=inbox)


@app.route('/process', methods=['POST'])
def process():
    if 'user' not in session:
        return redirect('/')

    current_user = session['user']
    action = request.form['action']
    msg_index = int(request.form['msg_index'])

    msg = messages[msg_index]

    if msg['type'] == 'key_exchange':
        peer_pubkey = users[msg['from']]['rsa'][1]
        valid = verify_signature(peer_pubkey, msg['auth_info'], msg['signed_info'])
        if not valid:
            return "Xác thực trao khóa thất bại!"

        des3_key = rsa_decrypt(users[current_user]['rsa'][0], msg['encrypted_3des_key'])
        users[current_user]['des3_key'] = des3_key
        users[current_user]['peer_rsa'] = peer_pubkey
        return redirect('/chat')

    elif msg['type'] == 'message':
        if not users[current_user]['des3_key']:
            return "Chưa có khóa 3DES, không thể giải mã."

        hash_check = sha256_hash(msg['iv'], msg['cipher'])
        if hash_check != msg['hash']:
            return "Message Integrity Compromised!"

        peer_pubkey = users[msg['from']]['rsa'][1]
        if not verify_signature(peer_pubkey, msg['hash'], msg['sig']):
            return "Chữ ký không hợp lệ!"

        decrypted = triple_des_decrypt(users[current_user]['des3_key'], msg['iv'], msg['cipher'])
        return render_template('verify.html', message=decrypted, valid=True)

    return "Hành động không hợp lệ!"


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
