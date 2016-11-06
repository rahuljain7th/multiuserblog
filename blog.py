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

# jinja2 file system has been used to get the template from dir
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
secret = "uda.raljulthnai7i$najx9jk5"


def hash_password(name, password, salt=None):
    """This Method is used to Hash The Password using sha256.
    The Following parameters are used to hash the password
    Args:
    name(str):username
    password(str):the password
    salt(str): The Random Five Digit String.Salt is optional parameter.
    Returns:
    String : salt | hash(name,password,salt)"""
    if not salt:
        salt = make_salt()
    logging.debug("hashing password %s", name + password + salt)
    h = hashlib.sha256(name + password + salt).hexdigest()
    pass_hashed = '%s|%s' % (salt, h)
    return pass_hashed


def valid_pw(name, password, pw_hash):
    """This Method is used to validate the password with hash password.
    It extracts the salt from hash password .
    name,passpword and salt is used to preprare hashed password.
    The hashed password is used to compare with inputed hashpassword.
    If it matches the password validation is successfull
    Args:
    name(Str):
    password(str)
    pw_hash(str)
    Returns:
    True or False"""
    salt = pw_hash.split('|')[0]
    if pw_hash == hash_password(name, password, salt):
        logging.debug("password hashing passed")
    return pw_hash == hash_password(name, password, salt)


def make_salt(length=5):
    """This Method is used to make random string of 5 digits"""
    return ''.join(random.choice(letters) for x in xrange(length))


class Handler(webapp2.RequestHandler):
    """This is Handler Class Which is extended by all classes
     to use default functions
    shared accross class.
    """
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def make_secure_val(self, val):
        """This Method is used to make Secure Value using hmac with secret key.
        Args:
        val:The value for which secure value should be made
        Returns:
        String: val | hmac value"""
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

    def check_secure_val(self, secure_val):
        """This Method is used to check the Validate the Secure Val
        Args: Secure_Value
        Returns : value which is not secured"""
        if secure_val:
            val = secure_val.split('|')[0]
            if secure_val == self.make_secure_val(val):
                return val

    def set_secure_cookie(self, name, val):
        """""This Method is used to set the secure cookie value
        Args:
        name:
        value: secured value of name
        Return name=secured value of name"""
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s;Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """This Method reads the cookie by name
        Ivokes check Secure value to get the cookie value if its secured.
        Args: name
        Retunrs:cookie value"""
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            self.check_secure_val(cookie_val)
            return cookie_val

    def getCookieValue(self, name):
        """This Method get the cookie by name
        Invokes get the cookie value if its secured.
        Args: name
        Retunrs:vaue from cookie value"""
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return self.check_secure_val(cookie_val)

    def login(self, user):
        """This Method is used to set the user key cookie on login
        Args: name
        Retunrs:NONE """
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """This method is used to remove the user-id key on logout"""
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def isvalid_login(self):
        """This Method is used to validate the user_cookie"""
        user_cookie = self.read_secure_cookie('user_id')
        user_id = self.check_secure_val(user_cookie)
        if user_id:
            return 'true'


class User(db.Model):
    """User DB Model of datastore
    Properties: username,passwordhased and email"""
    username = db.StringProperty(required=True)
    pass_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_name(cls, name):
        """To the the User from db by username"""
        u = User.all().filter('username =', name).get()
        logging.debug(u)
        return u

    @classmethod
    def register(cls, name, password, email=None):
        """This Method Store User Information in DB"""
        pass_hash = hash_password(name, password)
        user = User(username=name, pass_hash=pass_hash, email=email)
        return user

    @classmethod
    def by_id(cls, id):
        """To get the user by id"""
        user = User.get_by_id(int(id))
        return user

    @classmethod
    def login(cls, name, pw):
        """This Method is used to validate username and password of user"""
        logging.info("Logging Method")
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pass_hash):
            return u


class BlogData(db.Model):
    """BlogData Model of database
     Properties :
     blogTitle:title of blog
     Blog Description:description of blog
     created : date when was the blog created
     user : Which User has created the blog.User Info is Referenced
     totalLikes:Total Like of the blog"""
    blogTitle = db.StringProperty(required=True)
    blogDescription = db.TextProperty(required=True)
    created = db.DateProperty(auto_now_add=True)
    user = db.ReferenceProperty(User)
    totallikes = db.IntegerProperty(default=0, required=False)

    @classmethod
    def by_id(cls, id):
        """To Recieve the blog data by id"""
        blogData = BlogData.get_by_id(int(id))
        return blogData

    @classmethod
    def getCommentsofBlog(cls, blogData):
        """To Recieve the Comments of Blog from Comment
         table by blogdata Info"""
        commentList = db.GqlQuery(
            "SELECT * FROM  Comment WHERE blog=:1" +
            " ORDER BY date desc", blogData)
        return commentList

    @classmethod
    def incrementLike(cls, id):
        """This Method is used to increase the like of Blog"""
        logging.debug("Increasing the Like")
        blogData = BlogData.get_by_id(int(id))
        blogData.totallikes += 1
        blogData.put()
        return blogData.totallikes

    @classmethod
    def isPostAlreadyLikedByUser(cls, blogid, userid):
        """This Method Validates if a Post is Already Liked by the User"""
        q = LikeBlog.all().filter("userid =", userid).filter(
            "blogid =", blogid).get()
        logging.debug(q)
        if q and q.isLikedBlog:
            return True
        return False


class Comment(db.Model):
    """Comment Table created by DB which store the comments of blog"""
    commenttext = db.StringProperty(required=True)
    user = db.ReferenceProperty(User)
    blog = db.ReferenceProperty(BlogData)
    date = db.DateTimeProperty(auto_now_add=True)


class LikeBlog(db.Model):
    """Like Table created by DB to store
     where a particular user has liked the blog"""
    userid = db.StringProperty(required=True)
    blogid = db.StringProperty(required=True)
    isLikedBlog = db.BooleanProperty(default=False)


class BlogFormHandler(Handler):
    """This Handler is used to Get the Blog
     Form and to create a New Post of The blog"""
    def get(self):
        logging.info("Inside get method of BlogHandler")
        # to check whether its a valid Login.
        # If its Valid Show the Form.If not valid Login
        # Redirect to Login From
        if self.isvalid_login():
            self.render("blogform.html", blogData={})
        else:
            self.redirect('/login')

    def post(self):
        """To Post the New Post"""
        # Get the user Info for which blog post should be stored.
        user_id = self.getCookieValue("user_id")
        user = User.get_by_id(int(user_id))
        logging.info("Inside Post method of BlogHandler")
        # Getting the Blog Details
        blogTitle = self.request.get("title")
        blogDescription = self.request.get("blogtext")
        errorMap = {}
        # Building the error map if blog data is invalid
        if not (blogTitle and blogTitle.strip()):
            errorMap['blogTitle'] = "Please Provide the Blog Title"
        if not (blogDescription and blogDescription.strip()):
            errorMap['blogDescription'] = "Please Provide the Blog Decsription"
        # If Blog Data is Valid Storing the Blog Information in BlogData Table
        if blogTitle and blogDescription:
            blogData = BlogData(blogTitle=blogTitle,
                                blogDescription=blogDescription, user=user)
            blogData.put()
            blogId = str(blogData.key().id())
            self.redirect('/'+blogId)
        else:
            # if Blog data is invalid the Blog Form is Shown with error map.
            logging.info("Error While Submitting the Form %s", errorMap)
            self.render('blogform.html', error=errorMap, blogTitle=blogTitle,
                        blogDescription=blogDescription)


class GetAllBlog(Handler):
    """This Class is used to get All The Blog for Home page"""
    def get(self):
        blogAllData = db.GqlQuery(
            "SELECT * FROM  BlogData ORDER BY created desc")
        logging.info(blogAllData)
        user_cookie = self.read_secure_cookie('user_id')
        logging.debug("user_cookie %s", user_cookie)
        user_id = self.check_secure_val(user_cookie)
        logging.debug("user_id %s", user_id)
        # if its a Logged in User User Name will be shown to user
        if user_id:
            logging.info("user_cookie exists")
            user = User.by_id(user_id)
            self.render("index.html", blogAllData=blogAllData,
                        username=user.username)
        else:
            logging.info("user_cookie doesnt not exists")
            self.render("index.html", blogAllData=blogAllData)


class GetBlogbyId(Handler):
    """This class is uses to get the blog by blog Id"""
    def get(self, blogId):
        logging.info("Inside Get method of GetBlogbyId")
        blogData = BlogData.get_by_id(int(blogId))
        blogAllData = []
        blogAllData.append(blogData)
        logging.info(blogAllData)
        user_cookie = self.read_secure_cookie('user_id')
        logging.debug("user_cookie %s", user_cookie)
        user_id = self.check_secure_val(user_cookie)
        logging.debug("user_id %s", user_id)
        if user_id:
            logging.info("user_cookie exists")
            user = User.by_id(user_id)
            self.render("index.html", blogAllData=blogAllData,
                        username=user.username)
        else:
            logging.info("user_cookie doesnt not exists")
            self.render("index.html", blogAllData=blogAllData)


class SignupForm(Handler):
    """This Class is used to Handle the SignUp Functionality for user"""
    def get(self):
        """If its valid Login User will be redirected to SignUp Page"""
        if self.isvalid_login():
            self.redirect('/blog')
        else:
            """If its not valid login user will be shown signup form"""
            errormap = {}
            self.render('signupform.html', errormap=errormap, output={})

    def post(self):
        """Post the user details in User Table"""
        errormap = {}
        username = self.request.get('username')
        # validating the username
        self.validateUsername(username, errormap)

        password = self.request.get('password')
        # validating the password
        self.validatePassword(password, errormap)

        confirmpass = self.request.get('confirmpass')
        # validating the password with confirm password
        self.validateConfirmPass(password, confirmpass, errormap)

        # validating the email
        email = self.request.get('email')
        self.validateEmail(email, errormap)
        logging.debug(errormap)
        # if error map exists the SignUp form is shown with errors
        if errormap:
            self.render('signupform.html', errormap=errormap,
                        output={'username': username, 'email': email})
        else:
            # get the user by username to validate if username already exists
            u = User.by_name(username)
            if u:
                errormap['userexists'] = 'The user already exists'
                self.render('signupform.html', errormap=errormap,
                            output={'username': username, 'email': email})
            else:
                # if no user is found the user info is stored in user table
                u = User.register(username, password, email)
                u.put()
                self.login(u)
                self.redirect('/blog')

    def validateUsername(self, username, errormap):
        """Validating the Username"""
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        logging.debug("Test Vlaid User %s", USER_RE.match(username))
        if not username or (username and not USER_RE.match(username)):
            errormap['username'] = "UserName is Invalid"

    def validatePassword(self, password, errormap):
        """Validating the password"""
        PASS_RE = re.compile(r".{3,20}$")
        if not password or (password and not PASS_RE.match(password)):
            errormap['password'] = "Password is Invalid"

    def validateConfirmPass(self, password, confirmpass, errormap):
        """Validating the Confirm password"""
        PASS_RE = re.compile(r".{3,20}$")
        if (password != confirmpass):
            errormap['confirmpassword'] = "Confirm Password is Invalid"

    def validateEmail(self, email, errormap):
        """Validating the Email"""
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        if email and not EMAIL_RE.match(email):
            errormap['email'] = "Email is Invalid"


class Login(Handler):
    """This Class is used to handle the Login Functionality"""
    def get(self):
        """To get the Login Form"""
        if self.isvalid_login():
            self.redirect('/blog')
        else:
            self.render('loginform.html')

    def post(self):
        """Validating the Login Information Entered."""
        username = self.request.get('username')
        password = self.request.get('password')
        if username and password:
            u = User.login(username, password)
            if u:
                self.login(u)
                self.redirect('/blog')
            else:
                self.render('loginform.html', username=username,
                            invalidloginmsg="incorrect username" +
                            " or password provided")
        else:
            self.render('loginform.html', username=username,
                        invalidloginmsg="incorrect username" +
                        " or password provided")


class Logout(Handler):
    """To handle the Logou Functionality"""
    def get(self):
        self.logout()
        self.redirect('/blog')


class MyBlog(Handler):
    """To the Blog Data of a Particular User"""
    def get(self):
        if self.isvalid_login():
            logging.info("Inside Get method of MyBlog")
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            blogAllData = db.GqlQuery("SELECT * FROM  BlogData WHERE user=:1",
                                      user)
            self.render("index.html", blogAllData=blogAllData,
                        username=user.username)
        else:
            self.redirect('/blog')


class EditBlog(Handler):
    """To handle the Edit Functionality of Blog"""
    def get(self):
        """To get the blogform with prefilled information of blog"""
        if self.isvalid_login():
            blogId = self.request.get('blogId')
            blogData = BlogData.by_id(int(blogId))
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            if blogData.user and blogData.user.username == user.username:
                self.render("blogform.html", blogTitle=blogData.blogTitle,
                            blogDescription=blogData.blogDescription,
                            blogId=blogData.key().id())
            else:
                self.redirect('/login')
        else:
            self.redirect('/login')

    def post(self):
        """Posting the Updated Information of the Blog"""
        blogId = self.request.get('blogId')
        blogData = BlogData.by_id(int(blogId))
        user_id = self.getCookieValue("user_id")
        user = User.get_by_id(int(user_id))
        editblogTitle = self.request.get("title")
        editblogDescription = self.request.get("blogtext")
        errorMap = {}
        if not (editblogTitle and editblogTitle.strip()):
            errorMap['blogTitle'] = "Please Provide the Blog Title"
        if not (editblogDescription and editblogDescription.strip()):
            errorMap['blogDescription'] = "Please Provide the Blog Decsription"
        if (editblogTitle and editblogTitle.strip()) and (
             editblogDescription and editblogDescription.strip()):
            editblogData = BlogData(blogTitle=editblogTitle,
                                    blogDescription=editblogDescription,
                                    user=user)
            blogData.blogTitle = editblogTitle
            blogData.blogDescription = editblogDescription
            blogData.put()
            blogId = str(blogData.key().id())
            self.redirect('/'+blogId)
        else:
            logging.info("Error While Submitting the Form %s", errorMap,)
            self.render('blogform.html', error=errorMap,
                        blogTitle=editblogTitle,
                        blogDescription=editblogDescription)


class DeleteBlog(Handler):
    """To Handle the Delete Functionality of the Blog"""
    def post(self):
        blogId = self.request.get('blogId')
        blogData = BlogData.by_id(int(blogId))
        user_id = self.getCookieValue("user_id")
        user = User.get_by_id(int(user_id))
        if blogData.user and blogData.user.username == user.username:
            blogData.delete()
        self.redirect('/myblogs')


class CommentHandler(Handler):
    """To Handle the Comment Functionality of the Blog"""
    def post(self):
        logging.debug("Inside Comment handler Post method")
        data = json.loads(self.request.body)
        comment = data['comment']
        blogId = data['blogId']
        if self.isvalid_login():
            # TODO: Refactor to getUser Method Later to get user object
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            # TODO: Refactor to getBlogbyId method to getBlogData Object
            blogId = data['blogId']
            blogData = BlogData.by_id(int(blogId))
            comment = Comment(commenttext=comment,
                              user=user, blog=blogData)
            comment.put()
            self.response.out.write(json.dumps(({'commenttext':
                                                comment.commenttext})))
        else:
            logging.debug("Redirect to login")
            self.response.out.write(json.dumps(({'redirect': 'true'})))


class LikePostHandler(Handler):
    """To Handle the Like Functionality of the Blog"""
    def post(self):
        logging.debug("Liking the Post")
        data = json.loads(self.request.body)
        blogId = data['blogId']
        # check if user is loggedIn.
        if self.isvalid_login():
            user_id = self.getCookieValue("user_id")
            user = User.get_by_id(int(user_id))
            blogData = BlogData.by_id(int(blogId))
            if blogData.user and blogData.user.username != user.username:
                if blogData.isPostAlreadyLikedByUser(blogId, user_id):
                    self.response.out.write(json.dumps(({'errorMsg':
                                            'You Have Already Liked the Post'
                                                         })))
                else:
                    likeBlog = LikeBlog(userid=user_id,
                                        blogid=blogId, isLikedBlog=True)
                    likeBlog.put()
                    totallikes = blogData.incrementLike(blogId)
                    self.response.out.write(json.dumps(
                                           ({'totalLikes': totallikes})))
            else:
                self.response.out.write(json.dumps(
                                                  ({'errorMsg': 'You Cannot' +
                                                   'Like your own post'})))
        else:
            logging.debug("Redirect to login")
            self.response.out.write(json.dumps(
                                   ({'errorMsg': 'Login to Like Post'})))

"""Defining the Url Route to Handler"""
app = webapp2.WSGIApplication([
    ('/blog', GetAllBlog),
    ('/newpost', BlogFormHandler),
    (r'/(\d+)', GetBlogbyId),
    ('/signup', SignupForm),
    ('/login', Login),
    ('/logout', Logout),
    ('/myblogs', MyBlog),
    ('/editblog', EditBlog),
    ('/deleteblog', DeleteBlog),
    ('/comment', CommentHandler),
    ('/likepost', LikePostHandler),
    ('/', GetAllBlog)
    ], debug=True)
