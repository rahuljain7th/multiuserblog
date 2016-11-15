from bloghandler import BlogHandler
from google.appengine.ext import db
from models import user,post
from models.user import User
from models.post import BlogData
import logging

class GetAllBlog(BlogHandler):
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


class GetBlogbyId(BlogHandler):
    """This class is uses to get the blog by blog Id"""
    def get(self, blogId):
        logging.info("Inside Get method of GetBlogbyId")
        if blogId.isdigit():
            blogData = BlogData.get_by_id(int(blogId))
            if blogData:
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
            else:
                self.redirect('/blog')


class MyBlog(BlogHandler):
    """To get Blog Data of a Particular User"""
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
