from bloghandler import BlogHandler
from models import user,post
import logging

class Login(BlogHandler):
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


class Logout(BlogHandler):
    """To handle the Logou Functionality"""
    def get(self):
        self.logout()
        self.redirect('/blog')