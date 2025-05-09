from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, DateField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:202106hh@localhost/finance_forecaster'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    incomes = db.relationship('Income', backref='user', lazy=True)
    expenses = db.relationship('Expenses', backref='user', lazy=True)
    goals = db.relationship('Goals', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Expenses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Goals(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    current_amount = db.Column(db.Float, nullable=False, default=0.0)
    deadline = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class IncomeForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired(), Length(max=100)])
    date = DateField('Date', validators=[DataRequired()])
    submit = SubmitField('Add Income')

class ExpenseForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired(), Length(max=100)])
    category = SelectField('Category', choices=[('Food', 'Food'), ('Transport', 'Transport'), ('Entertainment', 'Entertainment'), ('Bills', 'Bills'), ('Other', 'Other')], validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    submit = SubmitField('Add Expense')

class GoalForm(FlaskForm):
    title = StringField('Goal Title', validators=[DataRequired(), Length(max=100)])
    target_amount = FloatField('Target Amount', validators=[DataRequired()])
    deadline = DateField('Deadline', validators=[DataRequired()])
    submit = SubmitField('Add Goal')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    income_form = IncomeForm()
    expense_form = ExpenseForm()
    goal_form = GoalForm()

    # Handle Income Form
    if income_form.validate_on_submit() and request.form.get('form_name') == 'income':
        income = Income(
            amount=income_form.amount.data,
            description=income_form.description.data,
            date=income_form.date.data,
            user_id=current_user.id
        )
        db.session.add(income)
        db.session.commit()
        flash('Income added successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Handle Expense Form
    if expense_form.validate_on_submit() and request.form.get('form_name') == 'expense':
        expense = Expenses(
            amount=expense_form.amount.data,
            description=expense_form.description.data,
            category=expense_form.category.data,
            date=expense_form.date.data,
            user_id=current_user.id
        )
        db.session.add(expense)
        db.session.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Handle Goal Form
    if goal_form.validate_on_submit() and request.form.get('form_name') == 'goal':
        goal = Goals(
            title=goal_form.title.data,
            target_amount=goal_form.target_amount.data,
            deadline=goal_form.deadline.data,
            user_id=current_user.id
        )
        db.session.add(goal)
        db.session.commit()
        flash('Goal added successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Fetch user data for display
    incomes = Income.query.filter_by(user_id=current_user.id).all()
    expenses = Expenses.query.filter_by(user_id=current_user.id).all()
    goals = Goals.query.filter_by(user_id=current_user.id).all()

    # Calculate totals for summary
    total_income = sum(income.amount for income in incomes)
    total_expenses = sum(expense.amount for expense in expenses)
    balance = total_income - total_expenses

    # Expense breakdown by category for pie chart
    expense_categories = {}
    for expense in expenses:
        expense_categories[expense.category] = expense_categories.get(expense.category, 0) + expense.amount

    return render_template(
        'dashboard.html',
        income_form=income_form,
        expense_form=expense_form,
        goal_form=goal_form,
        incomes=incomes,
        expenses=expenses,
        goals=goals,
        total_income=total_income,
        total_expenses=total_expenses,
        balance=balance,
        expense_categories=expense_categories
    )

# Create database tables
with app.app_context():
    db.drop_all()  # Drop existing tables to avoid conflicts
    db.create_all()  # Recreate tables with updated schema

if __name__ == '__main__':
    app.run(debug=True)