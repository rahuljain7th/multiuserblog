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
from postBlog import BlogFormHandler
from getBlog import GetAllBlog,GetBlogbyId,MyBlog
from signup import SignupForm
from login import Logout,Login
from comment import CommentHandler
from like import LikePostHandler

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


class BlogHandler(webapp2.RequestHandler):
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
