from google.appengine.ext import db
import logging
from handler import bloghandler

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
        pass_hash = bloghandler.hash_password(name, password)
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
        if u and bloghandler.valid_pw(name, pw, u.pass_hash):
            return u