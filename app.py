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
    ratings = db.relationship('Rating', backref='product', lazy=True)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    product = db.relationship('Product', backref='cart_items')

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
    products = Product.query.filter_by(enabled=True).limit(3).all()  # Featured products
    return render_template('index.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('¡Inicio de sesión exitoso!', 'success')
            return redirect(url_for('index'))
        flash('Credenciales inválidas', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('¡Sesión cerrada!', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('El nombre de usuario o correo ya está registrado.', 'danger')
            return render_template('register.html')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('¡Registro exitoso! Por favor, inicia sesión.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            # Placeholder for email sending (requires Flask-Mail)
            flash('Se ha enviado un enlace de recuperación a tu correo.', 'info')
        else:
            flash('Correo no registrado.', 'danger')
        return redirect(url_for('login'))
    return render_template('recover.html')

@app.route('/catalog', methods=['GET', 'POST'])
def catalog():
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('Por favor, inicia sesión para valorar productos.', 'warning')
            return redirect(url_for('login'))
        product_id = request.form.get('product_id')
        rating_value = int(request.form.get('rating'))
        comment = request.form.get('comment')
        rating = Rating(product_id=product_id, user_id=session['user_id'], rating=rating_value, comment=comment)
        db.session.add(rating)
        db.session.commit()
        flash('¡Valoración enviada!', 'success')
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
        flash('Por favor, inicia sesión para acceder al carrito.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'cart_item_id' in request.form:
            # Delete item from cart
            cart_item_id = request.form.get('cart_item_id')
            cart_item = CartItem.query.get_or_404(cart_item_id)
            if cart_item.user_id == session['user_id']:
                db.session.delete(cart_item)
                db.session.commit()
                flash('Producto eliminado del carrito.', 'success')
        else:
            # Add item to cart
            product_id = request.form.get('product_id')
            quantity = int(request.form.get('quantity'))
            product = Product.query.get_or_404(product_id)
            if product.stock < quantity:
                flash('No hay suficiente stock disponible.', 'danger')
                return redirect(url_for('catalog'))
            cart_item = CartItem(user_id=session['user_id'], product_id=product_id, quantity=quantity)
            db.session.add(cart_item)
            db.session.commit()
            flash('¡Producto añadido al carrito!', 'success')
    cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
    return render_template('cart.html', cart_items=cart_items)

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if 'user_id' not in session:
        flash('Por favor, inicia sesión para realizar el pago.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Placeholder for payment processing (e.g., Stripe)
        cart_items = CartItem.query.filter_by(user_id=session['user_id']).all()
        if not cart_items:
            flash('El carrito está vacío.', 'danger')
            return redirect(url_for('cart'))
        order = Order(user_id=session['user_id'])
        db.session.add(order)
        for item in cart_items:
            product = Product.query.get(item.product_id)
            product.stock -= item.quantity
            db.session.delete(item)
        db.session.commit()
        flash('¡Pago procesado exitosamente!', 'success')
        return redirect(url_for('tracking'))
    return render_template('payment.html')

@app.route('/tracking')
def tracking():
    if 'user_id' not in session:
        flash('Por favor, inicia sesión para ver tus pedidos.', 'warning')
        return redirect(url_for('login'))
    orders = Order.query.filter_by(user_id=session['user_id']).all()
    return render_template('tracking.html', orders=orders)

@app.route('/inventory')
def inventory():
    if 'role' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('index'))
    products = Product.query.all()
    low_stock = [p for p in products if p.stock < 10]  # Alert for low stock
    if low_stock:
        flash(f'Productos con bajo inventario: {", ".join(p.name for p in low_stock)}', 'warning')
    return render_template('inventory.html', products=products)

@app.route('/products', methods=['GET', 'POST'])
def products():
    if 'role' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        price = float(request.form.get('price'))
        category = request.form.get('category')
        stock = int(request.form.get('stock'))
        product = Product(name=name, description=description, price=price, category=category, stock=stock)
        db.session.add(product)
        db.session.commit()
        flash('¡Producto añadido!', 'success')
        return redirect(url_for('products'))
    products = Product.query.all()
    return render_template('products.html', products=products)

@app.route('/products/edit/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('index'))
    product = Product.query.get_or_404(id)
    if request.method == 'POST':
        product.name = request.form.get('name')
        product.description = request.form.get('description')
        product.price = float(request.form.get('price'))
        product.category = request.form.get('category')
        product.stock = int(request.form.get('stock'))
        product.enabled = 'enabled' in request.form
        db.session.commit()
        flash('¡Producto actualizado!', 'success')
        return redirect(url_for('products'))
    return render_template('products.html', products=Product.query.all(), edit_product=product)

@app.route('/products/delete/<int:id>', methods=['POST'])
def delete_product(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('index'))
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    flash('¡Producto eliminado!', 'success')
    return redirect(url_for('products'))

@app.route('/products/toggle/<int:id>', methods=['POST'])
def toggle_product(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('index'))
    product = Product.query.get_or_404(id)
    product.enabled = not product.enabled
    db.session.commit()
    flash(f'Producto {"habilitado" if product.enabled else "deshabilitado"}.', 'success')
    return redirect(url_for('products'))

@app.route('/suppliers', methods=['GET', 'POST'])
def suppliers():
    if 'role' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name')
        contact = request.form.get('contact')
        supplier = Supplier(name=name, contact=contact)
        db.session.add(supplier)
        db.session.commit()
        flash('¡Proveedor añadido!', 'success')
        return redirect(url_for('suppliers'))
    suppliers = Supplier.query.all()
    return render_template('suppliers.html', suppliers=suppliers)

@app.route('/suppliers/edit/<int:id>', methods=['GET', 'POST'])
def edit_supplier(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('index'))
    supplier = Supplier.query.get_or_404(id)
    if request.method == 'POST':
        supplier.name = request.form.get('name')
        supplier.contact = request.form.get('contact')
        supplier.enabled = 'enabled' in request.form
        db.session.commit()
        flash('¡Proveedor actualizado!', 'success')
        return redirect(url_for('suppliers'))
    return render_template('suppliers.html', suppliers=Supplier.query.all(), edit_supplier=supplier)

@app.route('/suppliers/delete/<int:id>', methods=['POST'])
def delete_supplier(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('index'))
    supplier = Supplier.query.get_or_404(id)
    db.session.delete(supplier)
    db.session.commit()
    flash('¡Proveedor eliminado!', 'success')
    return redirect(url_for('suppliers'))

@app.route('/suppliers/toggle/<int:id>', methods=['POST'])
def toggle_supplier(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('index'))
    supplier = Supplier.query.get_or_404(id)
    supplier.enabled = not supplier.enabled
    db.session.commit()
    flash(f'Proveedor {"habilitado" if supplier.enabled else "deshabilitado"}.', 'success')
    return redirect(url_for('suppliers'))

@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        # Placeholder for support ticket processing
        flash('¡Tu mensaje ha sido enviado al equipo de soporte!', 'success')
        return redirect(url_for('support'))
    return render_template('support.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Seed a sample product if none exist
        if not Product.query.first():
            product = Product(name="Laptop Pro", description="High-performance laptop", price=999.99, category="laptops", stock=50)
            db.session.add(product)
            db.session.commit()
    app.run(debug=True)