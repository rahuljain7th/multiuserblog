from bloghandler import BlogHandler
from models import user,post
import logging
import re
from models.user import User

class SignupForm(BlogHandler):
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
                logging.debug("User Already Exists")
                errormap['username'] = 'The user already exists'
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