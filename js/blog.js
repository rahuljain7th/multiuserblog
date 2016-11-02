 function postcomment(forminput) {
                $.ajax({
                  type: "POST",
                  url: "/comment",
                  dataType: 'json',
                  data: JSON.stringify({ "blogId": forminput.blogId.value,"comment":forminput.commentText.value})
                }).done(function(data) {

                    if(data.redirect) {
                        $(forminput).find('.error').append('<div class="errorMsg">please login to post</div>');
                    } else {
                    $(forminput).closest('.formcomment').find('.commentList').prepend('<ul><li><p>'+data['commenttext']+'</p></li></ul>');
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

