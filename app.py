from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import TextAreaField, StringField, SubmitField
import bleach

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SECRET_KEY'] = 'secret'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    language = db.Column(db.String(50), default='ta')
    posts = db.relationship('Post', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

    def set_password(self, password):
        """Hash the password and store it."""
        if password:
            self.password = generate_password_hash(password, method='sha256')
        else:
            raise ValueError("Password must not be None or empty")

    def check_password(self, password):
        """Check if the provided password matches the hashed password."""
        return check_password_hash(self.password, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    text = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.relationship('Like', backref='post', lazy=True)
    comments = db.relationship('Comment', backref='post', lazy=True)


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class PostForm(FlaskForm):
    content = TextAreaField('Content')
    language = StringField('Language')
    submit = SubmitField('Post')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def mainpage():
    language = session.get('language', current_user.language)
    if language not in ['ta', 'en']:
        language = 'en'

    posts = Post.query.all()
    user_likes = set(Like.query.filter_by(user_id=current_user.id).all())

    return render_template(f'{language}/mainpage.html', posts=posts, user_likes=user_likes)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            session['language'] = user.language
            return redirect(url_for('mainpage'))

        flash('Invalid credentials.')
        return redirect(url_for('login'))

    language = session.get('language', 'en')
    return render_template(f'{language}/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))

        new_user = User(username=username, language='en')
        try:
            new_user.set_password(password)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('register'))

        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('login'))
    language = session.get('language', 'en')
    return render_template(f'{language}/register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/postpage', methods=['GET', 'POST'])
@login_required
def postpage():
    if request.method == 'POST':
        title = request.form.get('title')
        raw_text = request.form.get('text')
        allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'strike']
        text = bleach.clean(raw_text, tags=allowed_tags, strip=True)
        language = request.form.get('language', current_user.language)

        if not title or not text:
            flash('Post title and content cannot be empty.')
            return redirect(url_for('postpage'))

        post = Post(title=title, text=text, user_id=current_user.id, language=language)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('search'))

    return render_template(f'{current_user.language}/postpage.html', author_name=current_user.username)

@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()

    if existing_like:
        db.session.delete(existing_like)
    else:
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(new_like)

    db.session.commit()
    
    likes_count = Like.query.filter_by(post_id=post_id).count()
    return redirect(url_for('search'))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        return jsonify({"error": "You do not have permission to delete this post"}), 403

    try:
        Like.query.filter_by(post_id=post.id).delete()
        Comment.query.filter_by(post_id=post.id).delete()
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for('search'))
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/comments/<int:post_id>', methods=['GET', 'POST'])
@login_required
def comments(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        text = request.form.get('comment_text')
        if not text:
            return redirect(url_for('comments', post_id=post_id))

        comment = Comment(text=text, post_id=post_id, user_id=current_user.id)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('comments', post_id=post_id))

    comments = Comment.query.filter_by(post_id=post_id).all()
    return render_template(f'{current_user.language}/comments.html', post=post, comments=comments)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    language = request.args.get('language', '')

    if language:
        posts = Post.query.filter(Post.text.contains(query), Post.language == language).all()
    else:
        posts = Post.query.filter(Post.text.contains(query)).all()
    language = session.get('language', 'en')
    return render_template(f'{language}/mainpage.html', posts=posts)

@app.route('/switch_language', methods=['POST'])
@login_required
def switch_language():
    new_language = 'en' if current_user.language == 'ta' else 'ta'
    current_user.language = new_language
    db.session.commit()
    session['language'] = new_language

    return redirect(url_for('mainpage'))

@app.route('/userprofile/<username>')
@login_required
def userprofile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template(f'{current_user.language}/userprofile.html', user=user)

@app.route('/userprofile/edit', methods=['GET', 'POST'])
@login_required
def edit_userprofile():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username:
            current_user.username = username
        if password:
            current_user.set_password(password)
        
        db.session.commit()
        return redirect(url_for('userprofile', username=current_user.username))

    return render_template(f'{current_user.language}/edit_userprofile.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
