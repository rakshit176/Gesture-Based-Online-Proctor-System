from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.fields.core import IntegerField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from app2 import app
import urllib.request
from flask import Flask, flash, request, redirect, url_for, render_template,Response
from flask import Flask, redirect, url_for, session,render_template
from werkzeug.utils import secure_filename
from flask_mail import Mail,Message
import cv2
import numpy as np
from keras import models
import sys
from PIL import Image
from datetime import timedelta
from authlib.integrations.flask_client import OAuth
import json
from camera import VideoCamera
from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room,leave_room
from flask import Flask, render_template, Response, jsonify, request
from camera import VideoCamera
from engineio.payload import Payload
Payload.max_decode_packets = 200
from flask import Flask, render_template, request, send_file, redirect, session,jsonify
import os
import sys
import json
from flask_fontawesome import FontAwesome
import zipfile
from werkzeug.utils import secure_filename
from hurry.filesize import size
from datetime import datetime
import filetype
from flask_qrcode import QRcode
from urllib.parse import unquote
import socket    
hostname = socket.gethostname()    
IPAddr = socket.gethostbyname(hostname)    
print("Your Computer Name is: " + hostname)    
print("Your Computer IP Address is: " + IPAddr)   
maxNameLength = 15


app = Flask(__name__)
# ====================Change me  =======================================
global client_id
global client_secret
app.config['SECRET_KEY'] = "thisismys3cr3tk3y"
video_camera = None
global_frame = None
socketio = SocketIO(app)


_users_in_room = {} # stores room wise user list
_room_of_sid = {} # stores room joined by an used
_name_of_sid = {} # stores display name of users


client_id = "79160910553-8qr388aideb71dskjofa4tgetv591tmq.apps.googleusercontent.com"
client_secret = "KRS6MszLTXbMzZRklZbOLCYm"
cap = cv2.VideoCapture(0)
classes = [
    'TurningRight',
           'NoActions',
           'TurningLeft']
model = models.load_model('D:/D/finalmodel3/modelGesture_3.h5')

mail =  Mail(app)
UPLOAD_FOLDER = 'D:/AProject2/static/Video_uploads/'
UPLOAD_FOLDER = 'D:/AProject2/static/Img_uploads/'

app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///D:/AProject2/newdatatable.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.secret_key = "secret key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['MAIL_SERVER'] ='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = "rakshitkumarkn@gmail.com"
app.config['MAIL_PASSWORD'] = "rakgo2260"
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Session config
app.secret_key = "something secret"
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
# ======================================================================
global capture,rec_frame, grey, switch, neg, face, rec, out 
capture=0
grey=0
neg=0
face=0
switch=1
rec=0

#make shots directory to save pics
try:
    os.mkdir('D:/AProject2/static/shots')
except OSError as error:
    pass

#Load pretrained face detection model    
net = cv2.dnn.readNetFromCaffe('D:/AProject2/saved_model/deploy.prototxt.txt', 'D:/AProject2/saved_model/res10_300x300_ssd_iter_140000.caffemodel')


# oAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=client_id,
    client_secret=client_secret,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)

mail =  Mail(app)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    regno = db.Column(db.String(80), unique=True)
    phno = db.Column(db.Integer)

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
fa = FontAwesome(app)

qrcode = QRcode(app)



app.secret_key = 'my_secret_key'

with open('D:/AProject2/config.json') as json_data_file:
    data = json.load(json_data_file)
hiddenList = data["Hidden"]
favList = data["Favorites"]
password = data["Password"]



currentDirectory=data["rootDir"]

osWindows = False #Not Windows

default_view = 0

tp_dict = {'image':'photo-icon.png','audio':'audio-icon.png','video':'video-icon.png'}

if 'win32' in sys.platform or 'win64' in sys.platform:
    osWindows = True



if(len(favList)>3):
    favList=favList[0:3]
    

def make_zipfile(output_filename, source_dir):
    relroot = os.path.abspath(os.path.join(source_dir, os.pardir))
    with zipfile.ZipFile(output_filename, "w", zipfile.ZIP_DEFLATED) as zip:
        for root, dirs, files in os.walk(source_dir):
            # add directory (needed for empty dirs)
            zip.write(root, os.path.relpath(root, relroot))
            for file in files:
                filename = os.path.join(root, file)
                if os.path.isfile(filename): # regular files only
                    arcname = os.path.join(os.path.relpath(root, relroot), file)
                    zip.write(filename, arcname)


def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class LoginForm2(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    regno = PasswordField('regno', validators=[InputRequired(), Length(min=7, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    phno = IntegerField('phno')

class RegisterForm2(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    regno = StringField('regno', validators=[InputRequired(), Length(min=7, max=80)])
    phno = IntegerField('phno')


class handy():
    def detect_face(frame, block=False, colour=(0, 255, 0)):
        fill = [4, -1][block]
        face_cascade = cv2.CascadeClassifier('D:/D/haarcascade_frontalface_default.xml')

        faces = face_cascade.detectMultiScale(frame, 1.1, 5)
        area = 0
        X = Y = W = H = 0
        for (x, y, w, h) in faces:
            if w * h > area:
                area = w * h
                X, Y, W, H = x, y, w, h
        cv2.rectangle(frame, (X, Y), (X + W, Y + H), colour, fill)    

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard2')
def dashboard2():
    flag,user = isLoggedIN()
    return render_template("Dashboard.html", flag=flag, user=user)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('Dashboard.html', name=current_user.username ,email = current_user.email)

def isLoggedIN():
    try:
        user = dict(session).get('profile', None)
        if user:
            return True, user.get("given_name")
        else:
            return False,{}
    except Exception as e:
        return False,{}


@app.route('/login2')
def login2():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')  # create the google oauth client
    token = google.authorize_access_token()  # Access token from google (needed to get user info)
    resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
    user_info = resp.json()
    user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
    session['profile'] = user_info
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    return redirect('dashboard2')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, password = form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
                

        return '<h1>Invalid user or password !</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password,phno=form.phno.data )  
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)


@app.route('/dashboard3')
def dashboard3():
    flag,user = isLoggedIN2()
    return render_template("studentDashboard.html", flag=flag, user=user)


@app.route('/dashboard4')
@login_required
def dashboard4():
    return render_template("studentDashboard.html", name=current_user.username ,email = current_user.email ,regno = current_user.regno)

def isLoggedIN2():
    try:
        user = dict(session).get('profile', None)
        if user:
            return True, user.get("given_name")
        else:
            return False,{}
    except Exception as e:
        return False,{}


@app.route('/login3')
def login3():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorize2', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize2')
def authorize2():
    google = oauth.create_client('google')  # create the google oauth client
    token = google.authorize_access_token()  # Access token from google (needed to get user info)
    resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
    user_info = resp.json()
    user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
    session['profile'] = user_info
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    return redirect('dashboard3')

@app.route('/login4', methods=['GET', 'POST'])
def login4():
    form = LoginForm2()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data , regno =form.regno.data).first()
        if user:
            if check_password_hash(user.password, password = form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard4'))
                

        return '<h1>Invalid user ,regno or password !</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('studentlogin.html',form=form )

@app.route('/signup2', methods=['GET', 'POST'])
def signup2():
    form = RegisterForm2()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, regno=form.regno.data, phno=form.phno.data )  
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New student user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('studentsignup.html', form=form)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.username ,email=current_user.email ,phno=current_user.phno)    

@app.route('/profile2')
@login_required
def profile2():
    return render_template('profile2.html', name=current_user.username ,email=current_user.email ,phno=current_user.phno, regno=current_user.regno)  

@app.route('/upload_from')
def upload_form():
	return render_template('Upload3.html')

@app.route('/upload_image', methods=['GET','POST'])
def upload_image():
	if 'file' not in request.files:
		flash('No file part')
		return redirect(request.url)
	file = request.files['file']
	if file.filename == '':
		flash('No image selected for uploading')
		return redirect(request.url)
	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		#print('upload_image filename: ' + filename)
		flash('Image successfully uploaded and displayed below')
		return render_template('Upload3.html', filename=filename)
	else:
		flash('Allowed image types are -> png, jpg, jpeg, gif')
		return redirect(request.url)

@app.route('/display_video/<filename>')
def display_image(filename):
	#print('display_image filename: ' + filename)
	return redirect(url_for('static', filename='Img_uploads/' + filename), code=301)

@app.route('/upload_video_from')
def upload_video_from():
	return render_template('Upload4.html')

@app.route('/upload_video', methods=['POST'])
def upload_video():
	if 'file' not in request.files:
		flash('No file part')
		return redirect(request.url)
	file = request.files['file']
	if file.filename == '':
		flash('No Video file selected for uploading')
		return redirect(request.url)
	else:
		filename = secure_filename(file.filename)
		file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		#print('upload_video filename: ' + filename)
		flash('Video successfully uploaded and displayed below')
		return render_template('Upload4.html', filename=filename)

@app.route('/display_video/<filename>')
def display_video(filename):
	#print('display_video filename: ' + filename)
	return redirect(url_for('static', filename='Video_uploads/' + filename), code=301)

@app.route('/home')
def home():
    return render_template('mail.html')

@app.route('/send_message', methods=['GET','POST'])
def send_message():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        msg = request.form['message']

        message = Message(subject, sender="rakshitkumarkn@gmail.com",recipients=[email])

        message.body = msg

        mail.send(message)

        success = "Your Message has been sent"

        return render_template('mail.html',success=success)

@app.route('/realindex')
def realindex():
    return render_template('support.html')


def markAttendance(name):
    with open('D:/AProject2/Attendance.csv','r+') as f:
        myDataList = f.readlines()
        nameList = []
        for line in myDataList:
            entry = line.split(',')
            nameList.append(entry[0])
            if name not in nameList:
                now = datetime.now()
                dtString = now.strftime('%H:%M:%S')
                f.writelines(f'\n{name},{dtString}')

@app.route('/gen_frames', methods=['POST','GET'])
def gen_frames():
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
    if not cap.isOpened():
        raise RuntimeError('Could not start camera.')
    while True:
        _, frame = cap.read()
        handy.detect_face(frame)
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        thresh = cv2.threshold(gray,120,255,cv2.THRESH_BINARY_INV+cv2.THRESH_OTSU)[1]
        mask = cv2.resize(thresh,(128,128))
        img_array = np.array(mask)
        img_array = np.stack((img_array,)*3, axis=-1)
        img_array_ex = np.expand_dims(img_array, axis=0)
        prediction = model.predict(img_array_ex)
        classe = classes[np.argmax(prediction)]
        markAttendance(classe)
        print('Classe = ',classe, 'Precision = ', np.amax(prediction)*100,'%')
        cv2.putText(frame, classe , (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2, 1)
        frame = cv2.resize(frame, (768, 576))
        frame = cv2.imencode('.jpg', frame)[1].tobytes()
        yield (b'--frame\r\n'b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')    
    

@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/realindex2')
def realindex2():
    return render_template('support2.html')

def markAttendance2(name):
    with open('D:/C/Project/Attendance.csv','r+') as f:
        myDataList = f.readlines()
        nameList = []
        for line in myDataList:
            entry = line.split(',')
            nameList.append(entry[0])
            if name not in nameList:
                now = datetime.now()
                dtString = now.strftime('%H:%M:%S')
                f.writelines(f'\n{name},{dtString}')

@app.route('/gen_frame', methods=['POST','GET'])

def gen_frame():
    video ='D:/AProject2/static/video.avi'
    cap = cv2.VideoCapture(video)
    if not cap.isOpened():
        raise RuntimeError('Could not start camera.')
    while True:
        retaining,frame = cap.read()
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        thresh = cv2.threshold(gray,120,255,cv2.THRESH_BINARY_INV+cv2.THRESH_OTSU)[1]
        mask = cv2.resize(thresh,(128,128))
        img_array = np.array(mask)
        img_array = np.stack((img_array,)*3, axis=-1)
        img_array_ex = np.expand_dims(img_array, axis=0)
        prediction = model.predict(img_array_ex)
        classe = classes[np.argmax(prediction)]
        print('Classe = ',classe, 'Precision = ', np.amax(prediction)*100,'%')
        cv2.putText(frame, classe , (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2, 1)
        markAttendance2(classe)

        frame = cv2.resize(frame, (768, 576))
        frame = cv2.imencode('.jpg', frame)[1].tobytes()
        yield (b'--frame\r\n'b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')    


@app.route('/video_feeds')
def video_feeds():
    return Response(gen_frame(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route("/videochat", methods=["GET", "POST"])
def videochat():
    if request.method == "POST":
        room_id = request.form['room_id']
        return redirect(url_for("entry_checkpoint", room_id=room_id))

    return render_template("home.html")

@app.route("/room/<string:room_id>/")
def enter_room(room_id):
    if room_id not in session:
        return redirect(url_for("entry_checkpoint", room_id=room_id))
    return render_template("chatroom.html", room_id=room_id, display_name=session[room_id]["name"], mute_audio=session[room_id]["mute_audio"], mute_video=session[room_id]["mute_video"])

@app.route("/room/<string:room_id>/checkpoint/", methods=["GET", "POST"])
def entry_checkpoint(room_id):
    if request.method == "POST":
        display_name = request.form['display_name']
        mute_audio = request.form['mute_audio']
        mute_video = request.form['mute_video']
        session[room_id] = {"name": display_name, "mute_audio":mute_audio, "mute_video":mute_video}
        return redirect(url_for("enter_room", room_id=room_id))

    return render_template("chatroom_checkpoint.html", room_id=room_id)
    
@socketio.on("connect")
def on_connect():
    sid = request.sid
    print("New socket connected ", sid)
    

@socketio.on("join-room")
def on_join_room(data):
    sid = request.sid
    room_id = data["room_id"]
    display_name = session[room_id]["name"]
    
    # register sid to the room
    join_room(room_id)
    _room_of_sid[sid] = room_id
    _name_of_sid[sid] = display_name
    
    # broadcast to others in the room
    print("[{}] New member joined: {}<{}>".format(room_id, display_name, sid))
    emit("user-connect", {"sid": sid, "name": display_name}, broadcast=True, include_self=False, room=room_id)
    
    # add to user list maintained on server
    if room_id not in _users_in_room:
        _users_in_room[room_id] = [sid]
        emit("user-list", {"my_id": sid}) # send own id only
    else:
        usrlist = {u_id:_name_of_sid[u_id] for u_id in _users_in_room[room_id]}
        emit("user-list", {"list": usrlist, "my_id": sid}) # send list of existing users to the new member
        _users_in_room[room_id].append(sid) # add new member to user list maintained on server

    print("\nusers: ", _users_in_room, "\n")


@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    room_id = _room_of_sid[sid]
    display_name = _name_of_sid[sid]

    print("[{}] Member left: {}<{}>".format(room_id, display_name, sid))
    emit("user-disconnect", {"sid": sid}, broadcast=True, include_self=False, room=room_id)

    _users_in_room[room_id].remove(sid)
    if len(_users_in_room[room_id]) == 0:
        _users_in_room.pop(room_id)

    _room_of_sid.pop(sid)
    _name_of_sid.pop(sid)

    print("\nusers: ", _users_in_room, "\n")


@socketio.on("data")
def on_data(data):
    sender_sid = data['sender_id']
    target_sid = data['target_id']
    if sender_sid != request.sid:
        print("[Not supposed to happen!] request.sid and sender_id don't match!!!")

    if data["type"] != "new-ice-candidate":
        print('{} message from {} to {}'.format(data["type"], sender_sid, target_sid))
    socketio.emit('data', data, room=target_sid)

@app.route('/video_record')
def video_record():
    return render_template('video_record.html')

@app.route('/record_status', methods=['POST'])
def record_status():
    global video_camera 
    if video_camera == None:
        video_camera = VideoCamera()

    json = request.get_json()

    status = json['status']

    if status == "true":
        video_camera.start_record()

        return jsonify(result="started")
    else:
        video_camera.stop_record()
        return jsonify(result="stopped")

@app.route('/video_stream', methods=['POST','GET'])
def video_stream():
    global video_camera 
    global global_frame

    if video_camera == None:
        video_camera = VideoCamera()
        
    while True:
        frame = video_camera.get_frame()

        if frame != None:
            global_frame = frame

            yield (b'--frame\r\n'
                    b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')
        else:
            yield (b'--frame\r\n'
                            b'Content-Type: image/jpeg\r\n\r\n' + global_frame + b'\r\n\r\n')

@app.route('/video_viewer')
def video_viewer():
    return Response(video_stream(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

camera = cv2.VideoCapture(0)

def gen_clip():  # generate frame by frame from camera
    global out, capture,rec_frame
    while True:
        success, frame = camera.read() 
        if success:
            if(capture):
                capture=0
                now = datetime.now()
                p = os.path.sep.join(['D:/AProject2/static/Img_uploads', "shot_{}.png".format(str(now).replace(":",''))])
                cv2.imwrite(p, frame)            
            try:
                ret, buffer = cv2.imencode('.jpg', cv2.flip(frame,1))
                frame = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            except Exception as e:
                pass
                
        else:
            pass


@app.route('/click')
def click():
    return render_template('click.html')
    
@app.route('/video_view')
def video_view():
    return Response(gen_clip(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/requests',methods=['POST','GET'])
def tasks():
    global switch,camera
    if request.method == 'POST':
        if request.form.get('click') == 'Capture':
            global capture
            capture=1
        elif  request.form.get('stop') == 'Stop/Start':
            
            if(switch==1):
                switch=0
                camera.release()
                cv2.destroyAllWindows()
                
            else:
                camera = cv2.VideoCapture(0)
                switch=1   

    elif request.method=='GET':
        return render_template('click.html')
    return render_template('click.html')


@app.route('/logout')
@login_required
def logout():
      for key in list(session.keys()):
        session.pop(key)
        logout_user()
        return redirect(url_for('index'))
        

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/login/')
@app.route('/login/<path:var>')
def loginMethod(var=""):
    global password


    if(password==''):
        session['login'] = True


    if('login' in session):
        return redirect('/homePage'+var)
    else:
        return render_template('login4.html')


@app.route('/login/', methods=['POST'])
@app.route('/login/<path:var>', methods=['POST'])
def loginPost(var = ""):
    global password



    text = request.form['text']
    if(text==password):
        session['login'] = True

        return redirect('/homePage'+var)
    else:
        return redirect('/login/'+var)

@app.route('/logout/')
def logoutMethod():
    if('login' in session):
        session.pop('login',None)
    return redirect('/login/')

def hidden(path):

    for i in hiddenList:
        if i != '' and i in path:
            return True
    
    return False



def changeDirectory(path):
    global currentDirectory, osWindows


    pathC = path.split('/')
    # print(path)

    if(osWindows):
        myPath = '//'.join(pathC)+'//'
    else:
        myPath = '/'+'/'.join(pathC)

    # print(myPath)
    myPath = unquote(myPath)
    # print("HELLO")
    # print(myPath)

    print(currentDirectory)
    
    try:
        os.chdir(myPath)
        ans=True
        if (osWindows):
            if(currentDirectory.replace('/','\\') not in os.getcwd()):
                ans = False
        else: 
            if(currentDirectory not in os.getcwd()):
                ans = False
    except:
        ans=False
    
    

    return ans
    

@app.route('/changeView')
def changeView():
    global default_view

    # print('view received')

    v = int(request.args.get('view', 0))

    if v in [0,1]:
        default_view = v
    else:
        default_view = 0


    return jsonify({
 
        "txt":default_view,
     
    })



def getDirList():
    # print(default_view)

    global maxNameLength,tp_dict,hostname

    dList = list(os.listdir('.'))
    dList= list(filter(lambda x: os.path.isdir(x), os.listdir('.')))
    dir_list_dict = {}
    fList = list(filter(lambda x: not os.path.isdir(x), os.listdir('.')))
    file_list_dict = {}
    curDir=os.getcwd()
    # print(os.stat(os.getcwd()))



    for i in dList:
        if(hidden(curDir+'/'+i)==False):
            image = 'folder5.png'

            if len(i)>maxNameLength:
                dots = "..."
            else:
                dots = ""

            dir_stats = os.stat(i)
            dir_list_dict[i]={}
            dir_list_dict[i]['f'] = i[0:maxNameLength]+dots
            dir_list_dict[i]['f_url'] = i
            dir_list_dict[i]['currentDir'] = curDir
            dir_list_dict[i]['f_complete'] = i
            dir_list_dict[i]['image'] = image
            dir_list_dict[i]['dtc'] = datetime.utcfromtimestamp(dir_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            dir_list_dict[i]['dtm'] = datetime.utcfromtimestamp(dir_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            dir_list_dict[i]['size'] = "---"


    for i in fList:
        if(hidden(curDir+'/'+i)==False):
            image = None
            try:
                kind = filetype.guess(i)

                if kind:
                    tp = kind.mime.split('/')[0]

                    if tp in tp_dict:
                        image = tp_dict[tp]
            except:
                pass

            if not image:
                image = 'file-test2.png'

            if len(i)>maxNameLength:
                dots = "..."
            else:
                dots = ""
        
            

            file_list_dict[i]={}
            file_list_dict[i]['f'] = i[0:maxNameLength]+dots
            file_list_dict[i]['f_url'] = i
            file_list_dict[i]['currentDir'] = curDir
            file_list_dict[i]['f_complete'] = i
            file_list_dict[i]['image'] = image

            try:
                dir_stats = os.stat(i)
                file_list_dict[i]['dtc'] = datetime.utcfromtimestamp(dir_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                file_list_dict[i]['dtm'] = datetime.utcfromtimestamp(dir_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                file_list_dict[i]['size'] = size(dir_stats.st_size)
            except:
                file_list_dict[i]['dtc'] = "---"
                file_list_dict[i]['dtm'] = "---"
                file_list_dict[i]['size'] = "---"


    return dir_list_dict,file_list_dict


def getFileList():

    dList = list(filter(lambda x: os.path.isfile(x), os.listdir('.')))

    finalList = []
    curDir=os.getcwd()

    for i in dList:
        if(hidden(curDir+'/'+i)==False):
            finalList.append(i)

    return(finalList)


@app.route('/files/', methods=['GET'])
@app.route('/files/<path:var>', methods=['GET'])
def filePage(var = "D:/AProject2/static/Img_uploads"):
    global default_view


    if('login' not in session):
        return redirect('/login8/files/'+var)

    # print(var)
    if(changeDirectory(var)==False):
        #Invalid Directory
        print("Directory Doesn't Exist")
        return render_template('404.html',errorCode=300,errorText='Invalid Directory Path',favList=favList)
     
    print(default_view)

    try:
        dir_dict,file_dict = getDirList()
        print(default_view)
        if default_view == 0:
            var1,var2 = "DISABLED",""
            default_view_css_1,default_view_css_2 = '','style=display:none'
        else:
            var1,var2 = "","DISABLED"
            default_view_css_1,default_view_css_2 = 'style=display:none',''


    except:
        return render_template('404.html',errorCode=200,errorText='Permission Denied',favList=favList)
    


    if osWindows:
        cList = var.split('/')
        var_path = '<a style = "color:black;"href = "/files/'+cList[0]+'">'+unquote(cList[0])+'</a>'
        for c in range(1,len(cList)):
            var_path += ' / <a style = "color:black;"href = "/files/'+'/'.join(cList[0:c+1])+'">'+unquote(cList[c])+'</a>'
        
    else:
        cList = var.split('/')
        var_path = '<a href = "/files/"><img src = "/static/root.png" style = "height:25px;width: 25px;">&nbsp;</a>'
        for c in range(0,len(cList)):
            var_path += ' / <a style = "color:black;"href = "/files/'+'/'.join(cList[0:c+1])+'">'+unquote(cList[c])+'</a>'


    return render_template('home2.html',currentDir=var,favList=favList,default_view_css_1=default_view_css_1,default_view_css_2=default_view_css_2,view0_button=var1,view1_button = var2,currentDir_path=var_path,dir_dict=dir_dict,file_dict=file_dict)



@app.route('/homePage', methods=['GET'])
def homePage():

    global currentDirectory, osWindows

    if('login' not in session):
        return redirect('/login/')
    
    print(currentDirectory)
    if osWindows:
        if(currentDirectory == ""):
            return redirect('/files/C:')
        else:
            # cura = currentDirectory

            cura='>'.join(currentDirectory.split('\\'))
            return redirect('/files/'+cura)
    else:
        return redirect('/files/'+currentDirectory)
        
        #REDIRECT TO UNTITLED OR C DRIVE FOR WINDOWS OR / FOR MAC



@app.route('/download/<path:var>')
def downloadFile(var):

    if('login' not in session):
        return redirect('/login/download/'+var)
    
    #os.chdir(currentDirectory)

    
    pathC = unquote(var).split('/')
    if(pathC[0]==''):
        pathC.remove(pathC[0])
    
    # if osWindows:
    #     fPath = currentDirectory+'//'.join(pathC)
    # else:
    #     fPath = '/'+currentDirectory+'//'.join(pathC)


    if osWindows:
        fPath = '//'.join(pathC)
    else:
        fPath = '/'+'//'.join(pathC)

    # print("HELLO")
    # print('//'.join(fPath.split("//")[0:-1]))
    # print(hidden('//'.join(fPath.split("//")[0:-1])))

    f_path_hidden = '//'.join(fPath.split("//")[0:-1])



    
    if(hidden(f_path_hidden) == True or changeDirectory(f_path_hidden)== False):
        #FILE HIDDEN
        return render_template('404.html',errorCode=100,errorText='File Hidden',favList=favList)


    fName=pathC[len(pathC)-1]
    #print(fPath)
    return send_file(fPath, download_name=fName)
    try:
        return send_file(fPath, download_name=fName)
    except:
        return render_template('404.html',errorCode=200,errorText='Permission Denied',favList=favList)



@app.route('/downloadFolder/<path:var>')
def downloadFolder(var):

    if('login' not in session):
        return redirect('/login/downloadFolder/'+var)
    

    pathC = var.split('/')
    if(pathC[0]==''):
        pathC.remove(pathC[0])
    
    if osWindows:
        fPath = '//'.join(pathC)
    else:
        fPath = '/'+'//'.join(pathC)
    
    
    
    f_path_hidden = '//'.join(fPath.split("//")[0:-1])
    
    if(hidden(f_path_hidden) == True or changeDirectory(f_path_hidden)== False):
        return render_template('404.html',errorCode=100,errorText='File Hidden',favList=favList)


    fName=pathC[len(pathC)-1]+'.zip'
    
    try:
        make_zipfile('C:\\Users\\reall\\Downloads\\temp\\abc.zip',os.getcwd())
        return send_file('C:\\Users\\reall\\Downloads\\temp\\abc.zip', attachment_filename=fName)
    except:
        return render_template('404.html',errorCode=200,errorText='Permission Denied',favList=favList)


@app.errorhandler(404)
def page_not_found(e):
    if('login' not in session):
        return redirect('/login/')
    
    return render_template('404.html',errorCode=404,errorText='Page Not Found',favList=favList), 404


@app.route('/upload/', methods = ['GET', 'POST'])
@app.route('/upload/<path:var>', methods = ['GET', 'POST'])
def uploadFile(var=""):

    if('login' not in session):
    
        return render_template('login4.html')

    text = ""
    if request.method == 'POST':
        pathC = var.split('/')

        if(pathC[0]==''):
            pathC.remove(pathC[0])
        

        if osWindows:
            fPath = +'//'.join(pathC)
        else:
            fPath = '/'+'//'.join(pathC)
    
        f_path_hidden = fPath


        if(hidden(f_path_hidden) == True or changeDirectory(f_path_hidden)== False):
            return render_template('404.html',errorCode=100,errorText='File Hidden',favList=favList)


        files = request.files.getlist('files[]') 
        fileNo=0
        for file in files:
            fupload = os.path.join(fPath,file.filename)

            if secure_filename(file.filename) and not os.path.exists(fupload):
                try:
                    file.save(fupload)    
                    print(file.filename + ' Uploaded')
                    text = text + file.filename + ' Uploaded<br>'
 
                    fileNo = fileNo +1
                except Exception as e:
                    print(file.filename + ' Failed with Exception '+str(e))
                    text = text + file.filename + ' Failed with Exception '+str(e) + '<br>'

                    continue
            else:
                print(file.filename + ' Failed because File Already Exists or File Type Issue')
                text = text + file.filename + ' Failed because File Already Exists or File Type not secure <br>'

            
          
    fileNo2 = len(files)-fileNo
    return render_template('uploadsuccess.html',text=text,fileNo=fileNo,fileNo2=fileNo2,favList=favList)



    
        

@app.route('/qr/<path:var>')
def qrFile(var):
    global hostname

    if('login' not in session):
        return redirect('/login/qr/'+var)
    
    #os.chdir(currentDirectory)
    
    
    pathC = unquote(var).split('/')
    if(pathC[0]==''):
        pathC.remove(pathC[0])
    

    if osWindows:
        fPath = '//'.join(pathC)
    else:
        fPath = '/'+'//'.join(pathC)

    
    f_path_hidden = '//'.join(fPath.split("//")[0:-1])
    
    if(hidden(f_path_hidden) == True or changeDirectory(f_path_hidden)== False):
        #FILE HIDDEN
        return render_template('404.html',errorCode=100,errorText='File Hidden',favList=favList)
    

    fName=pathC[len(pathC)-1]
    #print(fPath)
    # print(fPath)
    qr_text = 'http://'+hostname+"//download//"+fPath

    # print(qr_text)
    return send_file(qrcode(qr_text, mode="raw"), mimetype="image/png")
    return send_file(fPath, attachment_filename=fName)



if __name__ == '__main__':
    app.run(debug=True)

camera.release()
cv2.destroyAllWindows()     