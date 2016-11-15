from google.appengine.ext import db
from user import User
import logging

class LikeBlog(db.Model):
    """Like Table created by DB to store
     where a particular user has liked the blog"""
    userid = db.StringProperty(required=True)
    blogid = db.StringProperty(required=True)
    isLikedBlog = db.BooleanProperty(default=False)
