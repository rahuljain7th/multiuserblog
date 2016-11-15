 function postcomment(forminput) {
                $.ajax({
                  type: "POST",
                  url: "/comment",
                  dataType: 'json',
                  data: JSON.stringify({ "blogId": forminput.blogId.value,"comment":forminput.commentText.value})
                }).done(function(data) {

                    if(data.redirect) {
                        $(forminput).find('.error').append('<div class="errorMsg">please login to post</div>');
                    } else if(data.error) {
                        $(forminput).find('.error').append('<div class="errorMsg">This Blog Doesnt Exist</div>');
                    } else {
                        location.reload();
                    //$(forminput).closest('.formcomment').find('.commentList').prepend('<ul><li><p>'+data['commenttext']+'</p></li></ul>');
                }

                });
            }
            function increaseLike(blogId) {
                $.ajax({
                    type:"POST",
                    url:"/likepost",
                    dataType:'json',
                    data:JSON.stringify({"blogId":blogId})
                }).done(function(data) {
                    if(data.errorMsg) {
                        document.getElementById('errorMsg-'+blogId).innerHTML='<div class="errorMsg">'+data.errorMsg+'</div>';
                    } else {
                        document.getElementById('likecount-'+blogId).innerHTML=data.totalLikes;

                    }
                });
            }
           function deleteComment(commentId) {
    $.ajax({
                    type:"POST",
                    url:"/deleteComment",
                    dataType:'json',
                    data:JSON.stringify({"commentId":commentId})
                }).done(function(data) {
                    if(data.errorMsg) {
                        document.getElementById('errorMsg-'+commentId).innerHTML='<div class="errorMsg">'+data.errorMsg+'</div>';
                    } else {
                        location.reload();

                    }
                });
           }
         function editComment(forminput) {
    $.ajax({
                    type:"POST",
                    url:"/editComment",
                    dataType:'json',
                    data: JSON.stringify({ "commentId": forminput.commentModalId.value,"comment":forminput.commentText.value})
                }).done(function(data) {
                    $('#myModal'+forminput.commentModalId.value).modal('hide')
                    if(data.errorMsg) {
                        document.getElementById('errorMsg-'+forminput.commentModalId.value).innerHTML='<div class="errorMsg">'+data.errorMsg+'</div>';
                    } else {
                        location.reload();
                    }
                });
           }

              function postBlog(forminput) {
              if(forminput.blogId.value) {
                document.postblogform.action = "/editblog";
              } else {
                document.postblogform.action = "/newpost";
              }
           }