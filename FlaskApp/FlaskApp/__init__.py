import logging
from logging.handlers import SMTPHandler, RotatingFileHandler
import os
from flask import Flask,render_template, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager,login_user, logout_user, current_user, login_required,UserMixin
from flask_mail import Mail
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_mail import Mail,Message
from datetime import datetime
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from sqlalchemy import and_
import random
from threading import Thread
from hashlib import md5
from time import time
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, \
    TextAreaField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, \
    Length
from flask_wtf.file import FileField, FileRequired

#`````````````````````
#Config

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    POSTS_PER_PAGE = 16
    UPLOAD_FOLDER = os.path.join(basedir, 'app/static/')
    ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg','bmp'])

    #register email service from google
    #set up g suite
	#add MX service to ec2 www.cshopperstore.com
	#add alias for cshopperstore.com
    MAIL_SERVER='smtp.gmail.com'
    MAIL_PORT=465
    MAIL_USE_SSL=True
    MAIL_USERNAME = 'info@cshopperstore.com'
    MAIL_PASSWORD = 'OBGs#1234'
    ADMINS = ['info@cshopperstore.com']




#`````````````````````````````````````````````````````````````````````````````````````````
#emails


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)
	#print("test1")


def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(app, msg)).start()
    #print("test2")
def send_password_reset_email(user):
    #print("test3")
    token = user.get_reset_password_token()
    send_email('[ChaoqunWeb] Reset Your Password',
               sender=app.config['ADMINS'][0],
               recipients=[user.email],
               text_body=render_template('email/reset_password.txt',
                                         user=user, token=token),
               html_body=render_template('email/reset_password.html',
                                         user=user, token=token))
    #print("test4")


#init
#`````````````````````````````````````````````````````````````````````````````````````````
app = Flask(__name__)
app.config.from_object(Config)
bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
mail = Mail(app)

if not app.debug:

    print("Oh HI")
    print(basedir) 

    if not os.path.exists(basedir + '/logs'):
        os.mkdir(basedir + '/logs')
    file_handler = RotatingFileHandler(basedir + '/logs/ChaoqunWeb.log', maxBytes=10240,
                                       backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('ChaoqunWeb')



@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'Products': Products,'User':User,'Cart':Cart,"Transsummary":Transsummary,"Transdetail":Transdetail}






#``````````````````````````````
#form



class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')

class UplodProductform(FlaskForm):
    name = TextAreaField('Product Name', validators=[DataRequired()],render_kw={"rows": 2, "cols": 100})
    price = TextAreaField('Product Price', validators=[DataRequired()])
    count = TextAreaField('How Many', validators=[DataRequired()])
    image = FileField('Upload images',validators=[FileRequired()])
    describe = TextAreaField('Product Description', validators=[DataRequired()],render_kw={"rows": 30, "cols": 100})
    submit = SubmitField('Submit')

    def validate_name(self, name):
        prd = Products.query.filter_by(name=name.data).first()
        print("valid activated")
        if prd is not None:
            raise ValidationError('Please use a different product name.')

class SubmitTransForm(FlaskForm):
    name = TextAreaField('Name', validators=[DataRequired()],render_kw={"rows": 1, "cols": 100})
    addr = TextAreaField('Address', validators=[DataRequired()],render_kw={"rows": 1, "cols": 100})
    card=TextAreaField('Card Number', validators=[DataRequired()],render_kw={"rows": 1, "cols": 30})
    expmonth=TextAreaField('Expiration Month(01)', validators=[DataRequired()],render_kw={"rows":1, "cols": 2})
    expyear=TextAreaField('Expiration Year(2020)', validators=[DataRequired()],render_kw={"rows":1, "cols": 4})
    vcode=TextAreaField('Last 3 or 4 digits in the back', validators=[DataRequired()],render_kw={"rows":1, "cols": 4})
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email or use this email to find yout username.')




#`````````````````````````````````````````````````````````````````````````````````````````
#models

class Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    price = db.Column(db.Float)
    describe = db.Column(db.String(2000))
    imgname=db.Column(db.String(60))
    count= db.Column(db.Integer)
    def __repr__(self):
        return '<Name {}>'.format(self.name)


'''
shopingcart = db.Table(
    'shopingcart',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('prd_id', db.Integer, db.ForeignKey('products.id'))
)
'''

#shoping cart
#save user_id, pro_id
#delete when user_buy
#if want to buy later, save to
#saved items table/ to be done

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    count= db.Column(db.Integer)
    prd_id = db.Column(db.Integer, db.ForeignKey('products.id'),
        nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)

    def __repr__(self):
        return '<count {}>'.format(self.count)


#trans_summary
#'''
#transid
#userid(foreign)
#transno(data+money+666:201901011200666)
#money
#time
#paystatus
#shipstatus

class Transsummary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    money=db.Column(db.Float)
    transnum=db.Column(db.String(20))#8+8+4
    time=db.Column(db.String(8))

    shipname=db.Column(db.String(30))
    addr=db.Column(db.String(200))
    creditcard=db.Column(db.String(30)) #card number
    creditid=db.Column(db.String(4))  #3240 last 4 or 3
    creditexpmonth=db.Column(db.String(2)) #02
    creditexpyear=db.Column(db.String(4)) #2022

    paymentstatus=db.Column(db.String(100))#1 pay, 0 not pay -1 refund
    shipmentstatus=db.Column(db.String(100))#1ship 0 not ship -1 return back
    def __repr__(self):
        return '<count {}>'.format(self.transnum)



#trans_detail
#'''
#id
#transid(foreign)
#prd_id(foreign)

class Transdetail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trans_id = db.Column(db.Integer, db.ForeignKey('transsummary.id'),
        nullable=False)
    prd_id = db.Column(db.Integer, db.ForeignKey('products.id'),
        nullable=False)
    count= db.Column(db.Integer)
    def __repr__(self):
        return '<count {}>'.format(self.count)



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    '''
    mycart = db.relationship(
        'Products', secondary=shopingcart,
        primaryjoin=(shopingcart.c.user_id == id),
        secondaryjoin=(shopingcart.c.prd_id == Products.id),
        backref=db.backref('buyer', lazy='dynamic'), lazy='dynamic')
    '''
    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

    '''
    def addtocart(self, prd):
        if not self.is_in_cart(prd):
            self.mycart.append(prd)

    def remove(self, prd):
        if self.is_in_cart(prd):
            self.mycart.remove(prd)

    def is_in_cart(self, prd):
        return self.mycart.filter(
            shopingcart.c.prd_id == prd.id).count() > 0

    def all_in_my_carts(self):
        return self.mycart.order_by(Products.name.asc()).all()
    '''
#shoping cart
#save user_id, pro_id
#delete when user_buy
#if want to buy later, save to
#saved items table/ to be done






@login.user_loader
def load_user(id):
    return User.query.get(int(id))







#``````````````````````
#ValidationError

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500








#`````````````````````````````````````````````````````````````````````````````````````````
#route
@app.route('/', methods=['GET', 'POST'])

@app.route('/index', methods=['GET', 'POST'])
def index():
    #allproc=Products.query.all()
    #allproc[prd]='1.jpeg'

    page = request.args.get('page', 1, type=int)
    posts = Products.query.order_by(Products.name.asc()).paginate(
        page, app.config['POSTS_PER_PAGE'], False)

    groups=[]
    ingroup=[]
    cnt=0
    for i in posts.items:
        ingroup.append(i)
        cnt+=1
        if cnt==4:
            cnt=0
            groups.append(ingroup)
            ingroup=[]
    if not ingroup==[]:
        groups.append(ingroup)

    next_url = url_for('index', page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num) \
        if posts.has_prev else None

    return render_template('showimg.html', items=groups,next_url=next_url,
    prev_url=prev_url)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)

        if user.username=="shaochaoqun":
            return redirect(url_for('managerpage'))

        #remember where to login
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)

    return render_template('login.html', title='Sign In', form=form)

@app.route('/managerpage')
@login_required
def managerpage():
    if current_user.username=="shaochaoqun":
        return render_template('managerindex.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/submittransac/<sum>', methods=['GET', 'POST'])
@login_required
def submittransac(sum):
    form = SubmitTransForm()
    money=float(sum)
    date=datetime.now().strftime("%m%d%Y")
    sum_str="00000000"
    sum_int=sum.split(".")[0]
    sum_int_length=len(sum_int)
    sum_str=sum_str[:8-sum_int_length]+sum_int
    transacnumber=date+sum_str+str(random.randint(1000,9999))

    if form.validate_on_submit():
        #add to trans summary
        trans = Transsummary(user_id=current_user.id,money=money,transnum=transacnumber,time=date,
        shipname=form.name.data,addr=form.addr.data,
        creditcard=form.card.data,creditid=form.vcode.data,creditexpmonth=form.expmonth.data,creditexpyear=form.expyear.data,
        paymentstatus="confirmed",shipmentstatus="not shipped")
        db.session.add(trans)


        #add to detail
        thistrans = Transsummary.query.filter_by(transnum=transacnumber).first()
        #find all product and count
        allprds_and_id = Cart.query.filter_by(user_id=current_user.id).all()

        for item in allprds_and_id:
            transdetail = Transdetail(trans_id=thistrans.id,prd_id=item.prd_id,count=item.count)
            db.session.add(transdetail)


        #delete cart
        historydata=Cart.query.filter(Cart.user_id == current_user.id).all()
        for any in historydata:
            db.session.delete(any)


        #avaiable acount will be updated
        for i in allprds_and_id:
            prd = Products.query.filter_by(id=i.prd_id).first()
            prd.count-=i.count


        db.session.commit()

        #success
        flash('Congratulations, you buy these products! We will ship them for you!')
        return redirect(url_for('index'))
    return render_template('submittransac.html', title='Submit Transaction', form=form, money=money,transacnumber=transacnumber)


@app.route('/product/<productName>')
def product(productName):
    prod = Products.query.filter_by(name=productName).first_or_404()
    return render_template('productinfo.html', product=prod)


@app.route('/minusone/<productName>')
@login_required
def minusone(productName):
    prd = Products.query.filter_by(name=productName).first()
    historydata=Cart.query.filter(and_(Cart.prd_id == prd.id,Cart.user_id == current_user.id)).all()
    cnt=historydata[0].count
    if cnt>1:
        historydata[0].count-=1
        db.session.commit()
    if cnt==1:
        db.session.delete(historydata[0])
        db.session.commit()
    return redirect(url_for("showmycart"))


@app.route('/plusone/<productName>')
@login_required
def plusone(productName):
    prd = Products.query.filter_by(name=productName).first()
    historydata=Cart.query.filter(and_(Cart.prd_id == prd.id,Cart.user_id == current_user.id)).all()
    historydata[0].count+=1
    db.session.commit()
    return redirect(url_for("showmycart"))

@app.route('/tocart/<prdname>')
@login_required
def tocart(prdname):
    prd = Products.query.filter_by(name=prdname).first()



    historydata=Cart.query.filter(and_(Cart.prd_id == prd.id,Cart.user_id == current_user.id)).all()
    if len(historydata) > 0:
        historydata[0].count +=1
        db.session.commit()

    else:
        newp = Cart(count=1, prd_id=prd.id, user_id=current_user.id)
        db.session.add(newp)
        db.session.commit()

    flash('You added the product to cart!')
    return render_template('productinfo.html', product=prd)



@app.route('/managetrans')
@login_required
def managetrans():
    if current_user.username=="shaochaoqun":
        alltrans = Transsummary.query.all()
        return render_template('managertrans.html', trans=alltrans)
    else:
        return render_template('managertrans.html', trans=None)

@app.route('/paymentchoice/<transnum>',methods = ['POST', 'GET'])
@login_required
def paymentchoice(transnum):

    if current_user.username=="shaochaoqun":
        #update paymentstatus
        trans = Transsummary.query.filter_by(transnum=transnum).first()
        payselect = request.form.get('paymentselect')
        trans.paymentstatus=payselect.lower()


        if payselect.lower()=="cancelled" or payselect.lower()=="refund":
            allprds_and_id = Transdetail.query.filter_by(trans_id=trans.id).all()
            #avaiable acount will be updated
            for i in allprds_and_id:
                prd = Products.query.filter_by(id=i.prd_id).first()
                prd.count+=i.count

        db.session.commit()
        flash('You update payment status!')
        return redirect(url_for("transdetail",transnum=transnum))



@app.route('/changecount/<productid>',methods = ['POST', 'GET'])
@login_required
def changecount(productid):
    if current_user.username=="shaochaoqun":
        prd = Products.query.filter_by(id=productid).first()
        changed = request.form.get('changecount')
        prd.count=int(changed)
        db.session.commit()
        flash('You update count status!')
        return redirect(url_for("product",productName=prd.name))


@app.route('/changemoney/<productid>',methods = ['POST', 'GET'])
@login_required
def changemoney(productid):
    if current_user.username=="shaochaoqun":
        prd = Products.query.filter_by(id=productid).first()
        changed = request.form.get('changemoney')
        prd.price=int(changed)
        db.session.commit()
        flash('You update price!')
        return redirect(url_for("product",productName=prd.name))




@app.route('/deleteprod/<productid>',methods = ['POST', 'GET'])
@login_required
def deleteprod(productid):
    if current_user.username=="shaochaoqun":
        prd = Products.query.filter_by(id=productid).first()
        db.session.delete(prd)
        db.session.commit()
        flash('You delete the product!')
        return redirect(url_for("index"))





@app.route('/shipmentinfor/<transnum>',methods = ['POST', 'GET'])
@login_required
def shipmentinfor(transnum):
    if current_user.username=="shaochaoqun":
        trans = Transsummary.query.filter_by(transnum=transnum).first()
        shipselect = request.form.get('shipmentnumber')
        trans.shipmentstatus=shipselect.lower()
        db.session.commit()
        flash('You update shipment status!')
        return redirect(url_for("transdetail",transnum=transnum))

@app.route('/transdetail/<transnum>')
@login_required
def transdetail(transnum):
    trans = Transsummary.query.filter_by(transnum=transnum).first()
    allprod = Transdetail.query.filter_by(trans_id=trans.id).all()
    product=[]
    for i in allprod:
        item=[]
        prd = Products.query.filter_by(id=i.prd_id).first()
        if prd:
            item.append(prd.name)
            item.append(i.count)
            product.append(item)
    return render_template('detailtrans.html', product=product,transnum=transnum,paymentstatus=trans.paymentstatus,shipmentstatus=trans.shipmentstatus)


@app.route('/mytrans')
@login_required
def mytrans():
    alltrans = Transsummary.query.filter_by(user_id= current_user.id).all()
    return render_template('mytrans.html', trans=alltrans)


@app.route('/showmycart')
@login_required
def showmycart():

    allprds_and_id = Cart.query.filter_by(user_id=current_user.id).all()
    allprds=[]
    sumprice=0.0
    for i in allprds_and_id:
        each=[]

        prd = Products.query.filter_by(id=i.prd_id).first()
        each.append(prd.name)
        each.append(prd.price)
        each.append(i.count)
        sumprice+=float(prd.price)*int(i.count)
        each.append(prd.count)
        if (prd.count==None) or (int(i.count) > int(prd.count)):
            each.append("{} Not avaiable!".format(i.count))
        else:
            each.append(" ")
        allprds.append(each)

    #allprds=current_user.all_in_my_carts()
    '''
    allprds=[]
    for i in allprd:
        oneresult=[]
        oneresult.append(i)
        prd = Products.query.filter_by(name=i.name).first()
        if prd.count!=None:
            oneresult.append(prd.count)
        else:
            oneresult.append(0)
        allprds.append(oneresult)

    '''
    return render_template('mycart.html', product=allprds,sumprice=round(sumprice,2))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():

    if current_user.username=="shaochaoqun":

        form = UplodProductform()
        if form.validate_on_submit():

            fimage = form.image.data
            filename = secure_filename(fimage.filename)
            #fimage.save(filename)

            fileEnd=""
            if "." in filename:
                fileEnd=filename.split(".")[-1]

            if not fileEnd in app.config['ALLOWED_EXTENSIONS']:
                flash('File format '+fileEnd+' is not allowd!')
                return render_template('uploadprod.html', form=form)



            name=form.name.data
            name=name.replace("/"," ")
            savedImgName=name[:20]+"_img."+fileEnd
            fimage.save(
                app.config['UPLOAD_FOLDER']+"/"+savedImgName
            )

            #print(filename)
            describe=form.describe.data
            #describe=describe.replace("\r\n", "<br>")
            newp = Products(name=name, price=form.price.data, count=form.count.data,describe=describe,imgname=savedImgName)

            db.session.add(newp)
            db.session.commit()
            flash('Congratulations, you upload a new product!')
            return redirect(url_for('upload'))

        return render_template('uploadprod.html', form=form)









#export FLASK_APP=application.py
#app.run(host="0.0.0.0",port=80)
if __name__ == '__main__':
    app.run()
