import os
from datetime import datetime, date
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

from forms import LoginForm, RegisterForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo_list.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    todos = relationship("Todo", back_populates="author")


class Todo(db.Model):
    __tablename__ = "todos"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="todos")
    todo = db.Column(db.String(250), nullable=False)
    notes = db.Column(db.String(250), )
    created = db.Column(db.DateTime(250), )
    due_date = db.Column(db.DateTime(250), )
    checked = db.Column(db.Boolean)
    list_name = db.Column(db.String(250))


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/', methods=['POST', 'GET'])
def home():
    return render_template("index.html", current_user=current_user)


@login_required
@app.route('/update_todos', methods=['POST', 'GET'])
def update_todos():
    todo_list = Todo.query.filter_by(author_id=current_user.id).all()
    placeholder_date = date.today().strftime("%B %d, %Y")
    # TODO: if listname is updated, update data base
    # TODO: add due-date - add button that open calendar, then add due date to db
    if request.method == 'POST':
        if len(request.form['InputTodo']) > 0:
            todo_input = request.form['InputTodo']
            new_todo = Todo(author=current_user,
                            todo=todo_input,
                            created=datetime.now(),
                            checked=False,
                            list_name=request.form['list_name'])
            db.session.add(new_todo)
            db.session.commit()
        check_boxes = request.form.getlist('todo_list')

        # update list with newly added todo
        updated_todo_list = Todo.query.filter_by(author_id=current_user.id).all()
        # untick all boxes, make all false, then for each of the ticked boxes, change to true, then update inx html
        if check_boxes != []:
            print(f'the checkboxes are {check_boxes}')
            for each_todo in todo_list:
                each_todo.checked = False
            for check in check_boxes:
                todo = Todo.query.get(int(check))
                todo.checked = True
                db.session.commit()
        # TODO, MAKE FILTER so each list is separate

        return render_template("update_todo.html", current_user=current_user, todo_list=updated_todo_list,
                               placeholder=placeholder_date)

    return render_template("update_todo.html", current_user=current_user, todo_list=todo_list,
                           placeholder_date=placeholder_date)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("update_todos"))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('update_todos'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/delete_all')
def delete_all():
    Todo.query.filter_by(author_id=current_user.id).delete()
    db.session.commit()
    return redirect(request.referrer)


@app.route('/delete_one/<int:id>')
def delete_one(id):
    todo_row = Todo.query.get(id)
    db.session.delete(todo_row)
    db.session.commit()
    return redirect(request.referrer)


if __name__ == "__main__":
    app.run(debug=True)
