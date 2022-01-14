from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextField, TextAreaField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField("Your Name", validators=[DataRequired()])
    email = StringField("Your Email", validators=[DataRequired(), Email()])
    password = PasswordField("Your Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Your Email", validators=[DataRequired(), Email()])
    password = PasswordField("Your Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class CommentForm(FlaskForm):
    comment_text = TextAreaField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
