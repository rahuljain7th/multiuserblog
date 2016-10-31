import webapp2
import os
import jinja2
import logging
import re
import random
import hmac
import hashlib
import json
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

    def getCookieValue(self,name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return self.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def isvalid_login(self):
        user_cookie = self.read_secure_cookie('user_id')
        user_id = self.check_secure_val(user_cookie)
        if user_id:
            return 'true'

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

class BlogData(db.Model):
    blogTitle = db.StringProperty(required=True)
    blogDescription = db.TextProperty(required=True)
    created = db.DateProperty(auto_now_add = True)
    user = db.ReferenceProperty(User)
    totallikes = db.IntegerProperty(default = 0,required=False)

    @classmethod
    def by_id(cls,id):
        blogData = BlogData.get_by_id(int(id))
        return blogData

    @classmethod
    def getCommentsofBlog(cls,blogData):
        commentList = db.GqlQuery("SELECT * FROM  Comment WHERE blog=:1",blogData)
        return commentList;

    @classmethod
    def incrementLike(cls,id):
        logging.debug("Increasing the Like")
        blogData = BlogData.get_by_id(int(id))
        blogData.totallikes += 1
        blogData.put()
        return blogData.totallikes

    @classmethod
    def isPostAlreadyLikedByUser(cls,blogid,userid):
        islikedpost = db.GqlQuery("SELECT * FROM  LikeBlog WHERE blogid=:1 AND userid:2",blogid,userid)
        return islikedpost;


class Comment(db.Model):
     commenttext = db.StringProperty(required=True)
     user = db.ReferenceProperty(User)
     blog = db.ReferenceProperty(BlogData)

class LikeBlog(db.Model):
    userid = db.StringProperty(required=True)
    blogid = db.StringProperty(required=True)
    isLikedBlog = db.BooleanProperty(default = False)

class BlogFormHandler(Handler):

    def get(self):
        logging.info("Inside get method of BlogHandler")
        if self.isvalid_login():
            self.render("blogform.html",blogData={})
        else:
            self.redirect('/blog/login')

    def post(self):
        user_id = self.getCookieValue("user_id")
        user = User.get_by_id(int(user_id))
        logging.info("Inside Post method of BlogHandler")
        blogTitle = self.request.get("title");
        blogDescription = self.request.get("blogtext");
        errorMap = {}
        if not (blogTitle and blogTitle.strip()):
            errorMap['blogTitle'] = "Please Provide the Blog Title"
        if not (blogDescription and blogDescription.strip()):
            errorMap['blogDescription'] = "Please Provide the Blog Decsription"
        if blogTitle and blogDescription:
            blogData = BlogData(blogTitle=blogTitle,blogDescription=blogDescription,user=user)
            blogData.put()
            blogId = str(blogData.key().id());
            self.redirect('/blog/'+blogId)
        else:
            logging.info("Error While Submitting the Form %s",errorMap)
            self.render('blogform.html',error=errorMap,blogTitle=blogTitle,blogDescription=blogDescription)



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

class MyBlog(Handler):
    """docstring for ClassName"""
    def get(self):
        if self.isvalid_login():
            logging.info("Inside Get method of MyBlog")
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            blogAllData = db.GqlQuery("SELECT * FROM  BlogData WHERE user=:1",user)
            self.render("index.html",blogAllData=blogAllData,username=user.username)
        else:
            self.redirect('/blog')

class EditBlog(Handler):

    def get(self):
        if self.isvalid_login():
            blogId = self.request.get('blogId')
            blogData = BlogData.by_id(int(blogId))
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            if blogData.user and blogData.user.username == user.username:
                self.render("blogform.html",blogTitle=blogData.blogTitle,blogDescription=blogData.blogDescription,
                    blogId=blogData.key().id())
            else:
                self.redirect('/blog/login')
        else:
            self.redirect('/blog/login')

    def post(self):
        blogId = self.request.get('blogId')
        blogData = BlogData.by_id(int(blogId))
        user_id = self.getCookieValue("user_id")
        user = User.get_by_id(int(user_id))
        editblogTitle = self.request.get("title");
        editblogDescription = self.request.get("blogtext");
        errorMap = {}
        if not (editblogTitle and editblogTitle.strip()):
            errorMap['blogTitle'] = "Please Provide the Blog Title"
        if not (editblogDescription and editblogDescription.strip()):
            errorMap['blogDescription'] = "Please Provide the Blog Decsription"
        if (editblogTitle and editblogTitle.strip()) and (editblogDescription and editblogDescription.strip()):
            editblogData = BlogData(blogTitle=editblogTitle,blogDescription=editblogDescription,user=user)
            blogData.blogTitle = editblogTitle;
            blogData.blogDescription = editblogDescription;
            blogData.put()
            blogId = str(blogData.key().id());
            self.redirect('/blog/'+blogId)
        else:
            logging.info("Error While Submitting the Form %s",errorMap,)
            self.render('blogform.html',error=errorMap,blogTitle=editblogTitle,blogDescription=editblogDescription)

class DeleteBlog(Handler):
    def post(self):
        blogId = self.request.get('blogId')
        blogData = BlogData.by_id(int(blogId))
        user_id = self.getCookieValue("user_id")
        user = User.get_by_id(int(user_id))
        if blogData.user and blogData.user.username == user.username:
            blogData.delete()
            self.redirect('/blog')

class CommentHandler(Handler):
    """docstring for ClassName"""
    def post(self):
        logging.debug("Inside Comment handler Post method")
        data = json.loads(self.request.body)
        comment = data['comment']
        blogId = data['blogId']
        #check if user is loggedIn.
        if self.isvalid_login():
            #TODO: Refactor to getUser Method Later to get user object
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            #TODO: Refactor to getBlogbyId method to getBlogData Object
            blogId = data['blogId']
            blogData = BlogData.by_id(int(blogId))
            comment = Comment(commenttext=comment,user=user,blog=blogData)
            comment.put()
            self.response.out.write(json.dumps(({'commenttext': comment.commenttext})))
        else:
            logging.debug("Redirect to login")
            self.response.out.write(json.dumps(({'redirect': 'true'})))

class LikePostHandler(Handler):
    def post(self):
        logging.debug("Liking the Post")
        data = json.loads(self.request.body)
        blogId = data['blogId']
        #check if user is loggedIn.
        if self.isvalid_login():
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            blogData = BlogData.by_id(int(blogId))
            if blogData.user and blogData.user.username != user.username:
                likeBlog = LikeBlog(userid=user_id,blogid=blogId,isLikedBlog=True);
                likeBlog.put()
                totallikes = blogData.incrementLike(blogId)

                self.response.out.write(json.dumps(({'totalLikes': totallikes})))
            else:
                self.response.out.write(json.dumps(({'errorMsg': 'You Cannot Like your own post'})))
        else:
            logging.debug("Redirect to login")
            self.response.out.write(json.dumps(({'errorMsg': 'Login to Like Post'})))


app = webapp2.WSGIApplication([
    ('/blog', GetAllBlog)
    ,('/blog/newpost', BlogFormHandler)
    ,(r'/blog/(\d+)',GetBlogbyId)
    ,('/blog/signup', SignupForm)
    ,('/blog/login', Login)
    ,('/blog/logout', Logout)
    ,('/blog/myblogs', MyBlog)
    ,('/blog/editblog', EditBlog)
    ,('/blog/deleteblog', DeleteBlog)
    ,('/blog/comment', CommentHandler)
    ,('/blog/likepost', LikePostHandler)
    ], debug=True)