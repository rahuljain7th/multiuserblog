from bloghandler import BlogHandler
from models import user,post
import logging

class BlogFormHandler(BlogHandler):
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

class EditBlog(BlogHandler):
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

class DeleteBlog(BlogHandler):
    """To Handle the Delete Functionality of the Blog"""
    def post(self):
        blogId = self.request.get('blogId')
        blogData = BlogData.by_id(int(blogId))
        user_id = self.getCookieValue("user_id")
        user = User.get_by_id(int(user_id))
        if blogData.user and blogData.user.username == user.username:
            blogData.delete()
        self.redirect('/myblogs')