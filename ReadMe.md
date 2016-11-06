
#Multi User Blogger using Python,jinja2,Google DataStore.Google App Engine
1. Logged In User Can Add new blogs.The Blog
Url : http://host:port/blog --> Gives All blogs user has added order by latest blog
      http://host:port/blog/newpost --> Add New Blog
      http://host:port/blog/blogId ---> Retrive particlar blog by Id
2. SignUp Functionality of the Blog.Password is hashed using sha256 algorithm.
3. Login Functionality Of the Blog.User Id is Stored in the Cookie using hmac
4. Home Page Where User can see All Blogs
5. Logged In User Can Like and Comment on Blogs.
6. User Cant Like his own Post.
7. User Can update the Blog
8. User can Delete the Blog
9.Logout Functionality
10. Google datastore is used to store blog information
11. Google Cloud App engine is used for deployment(Included Batch Files to Deploy)
12. Demo at quickwrite-rahuljain7th.appspot.com
