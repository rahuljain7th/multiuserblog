from google.appengine.ext import db
from user import User
import logging
from models.like import LikeBlog

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