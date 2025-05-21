from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tecno_pro.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='client')  # client, admin, employee

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    enabled = db.Column(db.Boolean, default=True)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, shipped, delivered
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Supplier(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(120), nullable=False)
    enabled = db.Column(db.Boolean, default=True)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        email = request.form['email']
        # Placeholder for password recovery logic (e.g., send email)
        flash('Password recovery email sent!', 'info')
        return redirect(url_for('login'))
    return render_template('recover.html')

@app.route('/catalog')
def catalog():
    category = request.args.get('category')
    price_min = request.args.get('price_min', type=float)
    price_max = request.args.get('price_max', type=float)
    query = Product.query.filter_by(enabled=True)
    if category:
        query = query.filter_by(category=category)
    if price_min and price_max:
        query = query.filter(Product.price.between(price_min, price_max))
    products = query.all()
    return render_template('catalog.html', products=products)

@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if 'user_id' not in session:
        flash('Please log in to access your cart.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        product_id = request.form['product_id']
        quantity = int(request.form['quantity'])
        cart_item = CartItem(user_id=session['user_id'], product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
        db.session.commit()
        flash('Item added to cart!', 'success')
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    return render_template('cart.html', cart_items=cart_items)

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Placeholder for payment processing (e.g., integrate with Stripe)
        order = Order(user_id=session['user_id'])
        db.session.add(order)
        db.session.commit()
        flash('Payment processed successfully!', 'success')
        return redirect(url_for('tracking'))
    return render_template('payment.html')

@app.route('/tracking')
def tracking():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    orders = Order.query.filter_by(user_id=session['user_id']).all()
    return render_template('tracking.html', orders=orders)

@app.route('/inventory')
def inventory():
    if 'role' not in session or session['role'] != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    products = Product.query.all()
    return render_template('inventory.html', products=products)

@app.route('/products', methods=['GET', 'POST'])
def products():
    if 'role' not in session or session['role'] != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category']
        stock = int(request.form['stock'])
        product = Product(name=name, description=description, price=price, category=category, stock=stock)
        db.session.add(product)
        db.session.commit()
        flash('Product added!', 'success')
    return render_template('products.html')

@app.route('/suppliers', methods=['GET', 'POST'])
def suppliers():
    if 'role' not in session or session['role'] != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        contact = request.form['contact']
        supplier = Supplier(name=name, contact=contact)
        db.session.add(supplier)
        db.session.commit()
        flash('Supplier added!', 'success')
    suppliers = Supplier.query.all()
    return render_template('suppliers.html', suppliers=suppliers)

@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        # Placeholder for support ticket submission
        flash('Your message has been sent to support!', 'success')
        return redirect(url_for('support'))
    return render_template('support.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)