import webapp2
import os
import jinja2
import logging
import re
import random
import hmac
import hashlib
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))
secret = "uda.raljulthnai7i$najx9jk5"

def hash_password(name,password,salt = None):
    if not salt:
        salt = make_salt()
    logging.debug("hashing password %s",name+password+salt)
    h = hashlib.sha256(name+password+salt).hexdigest()
    pass_hashed = '%s|%s' %(salt,h)
    return pass_hashed

def valid_pw(name,password,pw_hash):
    salt = pw_hash.split('|')[0]
    if pw_hash == hash_password(name,password,salt):
        logging.debug("password hashing passed")
    return pw_hash == hash_password(name,password,salt)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))



class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.write(*a,**kw)

    def render_str(self,template,**params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def make_secure_val(self,val):
        return '%s|%s' % (val,hmac.new(secret,val).hexdigest())

    def check_secure_val(self,secure_val):
        if secure_val :
            val=secure_val.split('|')[0]
            if secure_val == self.make_secure_val(val):
                return val

    def set_secure_cookie(self,name,val):
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header(
        'Set-Cookie','%s=%s;Path=/'%(name,cookie_val))

    def read_secure_cookie(self,name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            self.check_secure_val(cookie_val)
            return cookie_val

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def isvalid_login(self):
        user_cookie = self.read_secure_cookie('user_id')
        user_id = self.check_secure_val(user_cookie)
        if user_id:
            return 'true'

class BlogData(db.Model):
    blogTitle = db.StringProperty(required=True)
    blogDescription = db.TextProperty(required=True)
    created = db.DateProperty(auto_now_add = True)

class BlogFormHandler(Handler):

    def get(self):
        logging.info("Inside get method of BlogHandler")
        if self.isvalid_login():
            self.render("blogform.html")
        else:
            self.redirect('/blog/login')

    def post(self):
        logging.info("Inside Post method of BlogHandler")
        blogTitle = self.request.get("title");
        blogDescription = self.request.get("blogtext");
        errorMap = {}
        if not blogTitle:
            errorMap['blogTitle'] = "Please Provide the Blog Title"
        if not blogDescription:
            errorMap['blogDescription'] = "Please Provide the Blog Decsription"
        if blogTitle and blogDescription:
            blogData = BlogData(blogTitle=blogTitle,blogDescription=blogDescription)
            blogData.put()
            blogId = str(blogData.key().id());
            self.redirect('/blog/'+blogId)
        else:
            logging.info("Error While Submitting the Form %s",errorMap)
            self.render('blogform.html',error=errorMap)



class GetAllBlog(Handler):
    def get(self):
        blogAllData = db.GqlQuery("SELECT * FROM  BlogData ORDER BY created desc")
        logging.info(blogAllData)
        user_cookie = self.read_secure_cookie('user_id')
        logging.debug("user_cookie %s",user_cookie)
        user_id = self.check_secure_val(user_cookie)
        logging.debug("user_id %s",user_id)
        if user_id:
            logging.info("user_cookie exists")
            user = User.by_id(user_id)
            self.render("index.html",blogAllData=blogAllData,username=user.username)
        else:
            logging.info("user_cookie doesnt not exists")
            self.render("index.html",blogAllData=blogAllData)

class GetBlogbyId(Handler):
    """docstring for ClassName"""
    def get(self, blogId):
        logging.info("Inside Get method of GetBlogbyId")
        #blogData = db.GqlQuery("SELECT * FROM  BlogData where blogId="+blogId)
        blogData = BlogData.get_by_id(int(blogId))
        blogAllData = []
        blogAllData.append(blogData)
        logging.info(blogAllData)
        self.render("index.html",blogAllData=blogAllData)

class User(db.Model):
    username = db.StringProperty(required=True)
    pass_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('username =', name).get()
        logging.debug(u)
        return u

    @classmethod
    def register(cls,name,password,email = None):
        pass_hash = hash_password(name,password)
        user = User(username=name,pass_hash=pass_hash,email=email)
        return user

    @classmethod
    def by_id(cls,id):
        user = User.get_by_id(int(id))
        return user;

    @classmethod
    def login(cls, name, pw):
        logging.info("Logging Method")
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pass_hash):
            return u

class SignupForm(Handler):
    def get(self):
         if self.isvalid_login():
            self.redirect('/blog')
         else:
            errormap = {}
            self.render('signupform.html',errormap=errormap,output={})


    def post(self):
        errormap = {}
        username = self.request.get('username')
        self.validateUsername(username,errormap)

        password = self.request.get('password')
        self.validatePassword(password,errormap)

        confirmpass = self.request.get('confirmpass')
        self.validateConfirmPass(password,confirmpass,errormap)

        email = self.request.get('email')
        self.validateEmail(email,errormap)
        logging.debug(errormap)
        if errormap:
            self.render('signupform.html',errormap=errormap,output={'username':username,'email':email})
        else:
            #check if user exists
            u = User.by_name(username)
            if u:
                errormap['userexists'] = 'The user already exists'
                self.render('signupform.html',errormap=errormap,output={'username':username,'email':email})
            else:
                u = User.register(username,password,email)
                u.put()
                self.login(u)
                self.redirect('/blog')

    def validateUsername(self,username,errormap):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        logging.debug("Test Vlaid User %s",USER_RE.match(username))
        if not username or (username and not USER_RE.match(username)):
            errormap['username']="UserName is Invalid"

    def validatePassword(self,password,errormap):
        PASS_RE = re.compile(r".{3,20}$")
        if not password or (password and not PASS_RE.match(password)):
            errormap['password']="Password is Invalid"

    def validateConfirmPass(self,password,confirmpass,errormap):
        PASS_RE = re.compile(r".{3,20}$")
        if (password != confirmpass):
            errormap['confirmpassword']="Confirm Password is Invalid"

    def validateEmail(self,email,errormap):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        if email and not EMAIL_RE.match(email):
            errormap['email']="Email is Invalid"

class Login(Handler):
    """docstring for ClassName"""
    def get(self):
        if self.isvalid_login():
            self.redirect('/blog')
        else:
            self.render('loginform.html')


    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if username and password:
            u = User.login(username,password);
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            self.render('loginform.html',username=username,invalidloginmsg="incorrect username"
                +" or password provided")

class Logout(Handler):
    """docstring for ClassName"""
    def get(self):
        self.logout()
        self.redirect('/blog')

app = webapp2.WSGIApplication([
    ('/blog', GetAllBlog)
    ,('/blog/newpost', BlogFormHandler)
    ,(r'/blog/(\d+)',GetBlogbyId)
    ,('/blog/signup', SignupForm)
    ,('/blog/login', Login)
    ,('/blog/logout', Logout)
    ], debug=True)