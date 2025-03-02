# Import necessary libraries
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, current_app
import pandas as pd
from io import StringIO
import csv
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import matplotlib.pyplot as plt
import matplotlib
from datetime import datetime, timedelta
matplotlib.use('Agg')
import seaborn as sns
from datetime import datetime
import os
from sqlalchemy import func

# Create the Flask app
app = Flask(__name__)

# Set secret key for security
app.config['SECRET_KEY'] = 'your-secret-key'

# Set database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:6399@localhost/inventory_db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:6399@localhost/inventory_db'
# Disable track modifications to prevent app overhead
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager(app)

# Set login view
login_manager.login_view = 'login'



class Bus(db.Model):
    """Define the Bus model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    bus_number = db.Column(db.String(50), nullable=False)  # Bus Number
    bus_number_plate = db.Column(db.String(50), nullable=False)  # Bus Number Plate
    manufacturer = db.Column(db.String(100), nullable=False)  # Manufacturer
    manufacturer_date = db.Column(db.Date, nullable=False)  # Manufacturer Date
    bought_date = db.Column(db.Date, nullable=False)  # Bought Date
class Part(db.Model):
    """Define the Part model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)  # Ensure this line is present
    quantity = db.Column(db.Integer, default=0)
    low_stock_threshold = db.Column(db.Integer, default=10)  # If you have this field

# Models
class User(UserMixin, db.Model):
    """Define the User model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Category(db.Model):
    """Define the Category model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    """Define the Product model."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    quantity = db.Column(db.Integer, default=0)
    price = db.Column(db.Float, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    low_stock_threshold = db.Column(db.Integer, default=10)

class Order(db.Model):
    """Define the Order model."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='PENDING')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', lazy=True)
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Correct usage of the session

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    product = db.relationship('Product', backref='order_items')

class Expenditure(db.Model):
    """Define the Expenditure model."""
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200))

class UserActivity(db.Model):
    """Define the UserActivity model to store user activities."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Define a relationship to the User model
    user = db.relationship('User', backref='activities')

class Fuel(db.Model):
    """Define the Fuel model for tracking fuel consumption."""
    id = db.Column(db.Integer, primary_key=True)
    bus_id = db.Column(db.Integer, db.ForeignKey('bus.id'), nullable=False)
    fuel_amount = db.Column(db.Float, nullable=False)  # Fuel amount in Liters
    reading = db.Column(db.Float, nullable=False)  # Reading in kilometers
    date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Define relationships
    bus = db.relationship('Bus', backref='fuel_records')
    user = db.relationship('User', backref='fuel_entries')
    


@app.route('/add_users', methods=['GET'])
def add_users():
    """Add predefined users to the database."""
    users = [
        {'name': 'Admin', 'email': 'admin@example.com', 'password': 'admin124', 'role': 'ADMIN'},
        {'name': 'Supervisor', 'email': 'supervisor@example.com', 'password': '123', 'role': 'SUPERVISOR'},
        {'name': 'Manager', 'email': 'manager@example.com', 'password': '123', 'role': 'MANAGER'},
        {'name': 'User ', 'email': 'user@gmail.com', 'password': '123', 'role': 'USER'},
    ]

    for user_data in users:
        # Check if the user already exists
        existing_user = User.query.filter_by(email=user_data['email']).first()
        if existing_user:
            continue  # Skip if the user already exists

        # Create a new user instance
        new_user = User(
            name=user_data['name'],
            email=user_data['email'],
            password=generate_password_hash(user_data['password']),  # Hash the password
            role=user_data['role']
        )
        db.session.add(new_user)

    db.session.commit()
    return "Users added successfully!"

# Custom decorators for role-based access control
def admin_required(f):
    """Decorator for admin-only access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'ADMIN':
            flash('You do not have permission to access this page ADMIN.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def manager_required(f):
    """Decorator for manager-only access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['ADMIN', 'MANAGER']:
            flash('You do not have permission to access this page MAN.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def supervisor_required(f):
    """Decorator for supervisor-only access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['ADMIN', 'MANAGER', 'SUPERVISOR']:
            flash('You do not have permission to access this page SUPER.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def log_user_activity(action, details=None):
    """Function to log user activity with detailed description."""
    if details:
        action = f"{action}: {details}"
    activity = UserActivity(user_id=current_user.id, action=action)
    db.session.add(activity)
    db.session.commit()

def format_db_action(action_type, item_type, item_name, extra_info=None):
    """Helper to format database action messages consistently."""
    msg = f"DB {action_type}: {item_type} '{item_name}'"
    if extra_info:
        msg += f" - {extra_info}"
    return msg

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login route."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            log_user_activity('logged in')
            if user.role in ['ADMIN', 'MANAGER', 'SUPERVISOR']:
                return redirect(url_for('reports'))
            else:
                return redirect(url_for('products'))
            
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout route."""
    log_user_activity('logged out')  # Log the activity only if the user is authenticated
    logout_user()
    return redirect(url_for('login'))

#@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard route."""
    log_user_activity('visited dashboard')
    
    # Fetch low stock products
    low_stock = Product.query.filter(Product.quantity <= Product.low_stock_threshold).all()
    
    # Get total counts
    total_products = Product.query.count()
    total_buses = Bus.query.count()
    total_categories = Category.query.count()
    
    # Fetch recent orders
    orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()

    # Fetch total sales by product
    total_sales = db.session.query(
        Product.name,
        db.func.sum(OrderItem.quantity).label('total_sales')
    ).join(OrderItem).join(Order).group_by(Product.id).all()

    # Prepare data for visualization
    products = [item[0] for item in total_sales]
    sales_values = [item[1] if item[1] is not None else 0 for item in total_sales]

    # Create a bar plot for total sales by product
    plt.figure(figsize=(10, 6))
    sns.barplot(x=products, y=sales_values, palette='viridis')
    plt.title('Total Sales by Product')
    plt.xlabel('Product')
    plt.ylabel('Total Sales')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('static/total_sales.png')  
    plt.close()

    # Fetch monthly expenditure data
    monthly_expenditure = db.session.query(
        db.func.date_format(Expenditure.date, '%Y-%m').label('month'),
        db.func.sum(Expenditure.amount).label('total_expenditure')
    ).group_by('month').all()

    # Prepare data for visualization
    months = [item[0] for item in monthly_expenditure]
    expenditure_values = [item[1] if item[1] is not None else 0 for item in monthly_expenditure]

    # Create a line plot for monthly expenditure
    plt.figure(figsize=(12, 6))
    sns.lineplot(x=months, y=expenditure_values, marker='o')
    plt.title('Monthly Expenditure')
    plt.xlabel('Month')
    plt.ylabel('Expenditure')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('static/monthly_expenditure.png')  
    plt.close()

    # Fetch daily sales data
    daily_sales = db.session.query(
        db.func.date(Order.created_at).label('date'),  
        db.func.sum(OrderItem.quantity).label('total_sales')
    ).join(OrderItem).group_by(db.func.date(Order.created_at)).order_by(db.func.date(Order.created_at)).all()

    # Prepare data for visualization
    dates = [record.date.strftime('%Y-%m-%d') for record in daily_sales]
    daily_sales_values = [record.total_sales for record in daily_sales]

    # Create a line plot for daily sales
    plt.figure(figsize=(12, 6))
    sns.lineplot(x=dates, y=daily_sales_values, marker='o')
    plt.title('Daily Sales')
    plt.xlabel('Date')
    plt.ylabel('Total Sales')
    plt.xticks(rotation=45)  
    plt.tight_layout()
    plt.savefig('static/daily_sales.png')  
    plt.close()

    return render_template('dashboard.html', 
        low_stock=low_stock,
        total_products=total_products,
        total_buses=total_buses,
        total_categories=total_categories,
        orders=orders
    )

@app.route('/users')
@admin_required
def users():
    """Users route."""
    log_user_activity('visited users')
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    """Add user route."""
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        user = User(name=name, email=email, password=generate_password_hash(password), role=role)
        db.session.add(user)
        db.session.commit()
        
        flash('User added successfully', 'success')
        log_user_activity(f'added user {user.name}')
        return redirect(url_for('users'))
    
    return render_template('add_user.html')

@app.route('/products')
@login_required
def products():
    """Products route."""
    log_user_activity('visited products')
    
    # Get search parameters
    search = request.args.get('search', '')
    category_id = request.args.get('category', type=int)
    
    # Base query
    query = Product.query
    
    # Apply category filter if provided
    if category_id:
        query = query.filter(Product.category_id == category_id)
    
    # Apply search if provided
    if search:
        search_terms = search.lower().split()
        for term in search_terms:
            query = query.filter(
                db.or_(
                    Product.name.ilike(f'%{term}%'),
                    Product.description.ilike(f'%{term}%')
                )
            )
    
    # Get all products and categories
    products = query.all()
    categories = Category.query.all()
    
    return render_template('products.html', 
        products=products, 
        categories=categories,
        search=search,
        selected_category=category_id
    )

@app.route('/products/add', methods=['POST'])
def add_product():
    """Add product route."""
    product_id = request.form.get('product_id')
    
    if product_id:  # If product_id exists, we're updating quantity
        try:
            quantity = int(request.form.get('quantity'))
            if quantity <= 0:
                flash('Quantity must be greater than 0', 'error')
                return redirect(url_for('products'))
                
            product = Product.query.get(product_id)
            if product:
                old_quantity = product.quantity
                product.quantity += quantity
                db.session.commit()
                log_user_activity('DB UPDATE', format_db_action('UPDATE', 'Product', product.name, 
                    f"Quantity updated from {old_quantity} to {product.quantity}"))
                flash('Product quantity updated successfully','success')
            else:
                flash('Product not found', 'error')
        except ValueError:
            flash('Invalid quantity value', 'error')
            return redirect(url_for('products'))
    else:  # If no product_id, we're creating a new product
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            quantity = int(request.form.get('quantity'))
            price = float(request.form.get('price'))
            category_id = int(request.form.get('category_id'))
            low_stock_threshold = int(request.form.get('low_stock_threshold'))
            
            # Validate inputs
            if quantity < 0:
                flash('Quantity cannot be negative', 'error')
                return redirect(url_for('products'))
            if price <= 0:
                flash('Price must be greater than 0', 'error')
                return redirect(url_for('products'))
            if low_stock_threshold < 0:
                flash('Low stock threshold cannot be negative', 'error')
                return redirect(url_for('products'))
                
            # Check for duplicate product name
            existing_product = Product.query.filter_by(name=name).first()
            if existing_product:
                flash('A product with this name already exists', 'error')
                return redirect(url_for('products'))
            
            product = Product(
                name=name,
                description=description,
                quantity=quantity,
                price=price,
                category_id=category_id,
                low_stock_threshold=low_stock_threshold
            )
            db.session.add(product)
            db.session.commit()
            log_user_activity('DB CREATE', format_db_action('CREATE', 'Product', name, 
                f"Qty: {quantity}, Price: ₹{price}, Category: {Category.query.get(category_id).name}, Low Stock Threshold: {low_stock_threshold}"))
            flash('New product added successfully', 'success')
        except ValueError:
            flash('Invalid input values', 'error')
            return redirect(url_for('products'))
    return redirect(url_for('products'))

@app.route('/categories')
@login_required
def categories():
    """Categories route."""
    log_user_activity('visited categories')
    categories = Category.query.all()
    products = Product.query.all()

    return render_template('categories.html', categories=categories)

@app.route('/categories/add', methods=['POST'])
#@manager_required
@login_required
def add_category():
    """Add category route."""
    name = request.form.get('name')
    description = request.form.get('description')
    
    # Check for duplicate category name
    existing_category = Category.query.filter_by(name=name).first()
    if existing_category:
        flash('A category with this name already exists', 'error')
        return redirect(url_for('categories'))
    
    category = Category(name=name, description=description)
    db.session.add(category)
    db.session.commit()
    log_user_activity('DB CREATE', format_db_action('CREATE', 'Category', name))
    flash('Category added successfully', 'success')
    return redirect(url_for('categories'))

@app.route('/orders')
@login_required
def orders():
    """Orders route."""
    log_user_activity('visited orders')
    
    # Get filter and pagination parameters from request
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of items per page

    # Base query
    if current_user.role in ['ADMIN', 'SUPERVISOR', 'MANAGER']:
        query = Order.query.join(User).add_columns(User.name, User.role)
    else:
        query = Order.query.filter_by(user_id=current_user.id).join(User).add_columns(User.name, User.role)

    # Apply search filter if provided
    if search:
        search_terms = search.lower().split()
        for term in search_terms:
            query = query.filter(
                db.or_(
                    Order.id.cast(db.String).ilike(f'%{term}%'),
                    User.name.ilike(f'%{term}%'),
                    User.role.ilike(f'%{term}%'),
                    Order.status.ilike(f'%{term}%')
                )
            )

    # Apply status filter if provided
    if status and status != 'all':
        query = query.filter(Order.status == status.upper())

    # Apply sorting
    query = query.order_by(Order.id.desc())

    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    orders = pagination.items

    products = Product.query.all()
    categories = Category.query.all()  # Get all categories
    return render_template(
        'orders.html',
        orders=orders,
        products=products,
        categories=categories,  # Pass categories to template
        search=search,
        status=status,
        pagination=pagination,
        min=min  # Add the min function to the template context
    )

@app.route('/orders/create', methods=['POST'])
@login_required
#@manager_required
def create_order():
    """Create order route."""
    order = Order(user_id=current_user.id)
    
    # Loop through all selected products
    for key in request.form:
        if key.startswith('quantity_'):
            product_id = key.split('_')[1]
            quantity = int(request.form.get(key))
            
            # Remove the limit on quantity for order creation

            order_item = OrderItem(product_id=product_id, quantity=quantity)
            order.items.append(order_item)

            # Record expenditure
            product = Product.query.get(product_id)
            if product:
                expenditure_amount = product.price * quantity
                expenditure = Expenditure(amount=expenditure_amount, 
                                          date=datetime.utcnow(), 
                                          description=f'Order created for {quantity} of {product.name}')
                db.session.add(expenditure)

    # Calculate total order value
    total_value = sum(item.quantity * Product.query.get(item.product_id).price for item in order.items)
    
    db.session.add(order)
    db.session.commit()
    
    # Log order creation with details
    items_detail = [f"{Product.query.get(item.product_id).name} (x{item.quantity})" for item in order.items]
    log_user_activity('DB CREATE', format_db_action('CREATE', 'Order', f"#{order.id}",
        f"Items: {', '.join(items_detail)} | Total Value: ₹{total_value:.2f}"))
    
    flash('Order created successfully', 'success')
    return redirect(url_for('orders'))


@app.route('/orders/<int:order_id>/details')
@login_required
def get_order_details(order_id):
    """Get order details route."""
    order = Order.query.get_or_404(order_id)
    
    # Check if user has permission to view details
    if current_user.role.upper() not in ['ADMIN', 'SUPERVISOR', 'MANAGER']:
        return jsonify({'error': 'Permission denied'}), 403
    
    # Get order items with product details
    items = db.session.query(
        OrderItem, Product
    ).join(Product).filter(OrderItem.order_id == order_id).all()
    
    # Format the data
    order_details = {
        'id': order.id,
        'status': order.status,
        'created_at': order.created_at.strftime('%Y-%m-%d %H:%M'),
        'items': [{
            'product_name': item.Product.name,
            'quantity': item.OrderItem.quantity,
            'price': item.Product.price,
            'total': item.OrderItem.quantity * item.Product.price
        } for item in items]
    }
    
    return jsonify(order_details)

@app.route('/orders/<int:order_id>/update-status', methods=['POST'])
@manager_required
def update_order_status(order_id):
    """Update order status route."""
    order = Order.query.get_or_404(order_id)
    status = request.form.get('status')
    
    if status in ['PENDING', 'APPROVED', 'REJECTED', 'COMPLETED']:
        old_status = order.status
        order.status = status
        db.session.commit()
        log_user_activity('DB UPDATE', format_db_action('UPDATE', 'Order', f"#{order.id}",
            f"Status changed: {old_status} -> {status}"))
        flash('Order status updated successfully', 'success')
    
    return redirect(url_for('orders'))

@app.route('/')
@app.route('/reports')
@login_required
def reports():
    """Reports route."""
    log_user_activity('visited reports')
    
    # Existing report data
    low_stock = Product.query.filter(Product.quantity <= Product.low_stock_threshold).all()
    total_inventory_value = db.session.query(func.sum(Product.quantity * Product.price)).scalar() or 0
    
    # New detailed report data
    today = datetime.now().date()
    last_week = today - timedelta(days=7)
    last_month = today - timedelta(days=30)

    # Weekly usage
    weekly_usage = db.session.query(
        func.sum(OrderItem.quantity)
    ).join(Order).filter(Order.created_at >= last_week).scalar() or 0

    # Monthly usage
    monthly_usage = db.session.query(
        func.sum(OrderItem.quantity)
    ).join(Order).filter(Order.created_at >= last_month).scalar() or 0

    # Top used items
    top_items = db.session.query(
        Product.name,
        func.sum(OrderItem.quantity).label('total_quantity'),
        func.sum(OrderItem.quantity * Product.price).label('total_cost')
    ).join(OrderItem).join(Order).filter(Order.created_at >= last_month).group_by(Product.id).order_by(func.sum(OrderItem.quantity).desc()).limit(5).all()

    # Recent expenditures
    recent_expenditures = Expenditure.query.order_by(Expenditure.date.desc()).limit(5).all()

    # Total expenditure
    total_expenditure = db.session.query(func.sum(Expenditure.amount)).scalar() or 0

    # Order counts (this was missing in the previous version)
    order_counts = db.session.query(Order.status, db.func.count(Order.id).label('count')).group_by(Order.status).all()
    order_counts_list = [{'status': status, 'count': count} for status, count in order_counts]

    return render_template(
        'reports.html', 
        low_stock=low_stock,
        total_inventory_value=total_inventory_value,
        weekly_usage=weekly_usage,
        monthly_usage=monthly_usage,
        top_items=top_items,
        recent_expenditures=recent_expenditures,
        total_expenditure=total_expenditure,
        order_counts=order_counts_list
    )

@app.route('/api/chart-data')
@login_required
def chart_data():
    # Fetch data for charts
    usage_data = db.session.query(
        func.date(Order.created_at).label('date'),
        func.sum(OrderItem.quantity).label('total_usage')
    ).join(OrderItem).group_by(func.date(Order.created_at)).order_by(func.date(Order.created_at)).all()

    expenditure_data = db.session.query(
        Expenditure.date,
        func.sum(Expenditure.amount).label('total_expenditure')
    ).group_by(Expenditure.date).order_by(Expenditure.date).all()

    category_data = db.session.query(
        Category.name,
        func.count(Product.id).label('count')
    ).join(Product).group_by(Category.id).all()

    stock_level_data = db.session.query(
        Product.name,
        Product.quantity.label('current_stock'),
        Product.low_stock_threshold.label('threshold')
    ).order_by(Product.quantity).limit(10).all()

    return jsonify({
        'usage': [{'date': str(item.date), 'total': int(item.total_usage)} for item in usage_data],
        'expenditures': [{'date': str(item.date), 'total': float(item.total_expenditure)} for item in expenditure_data],
        'categories': [{'name': item.name, 'count': int(item.count)} for item in category_data],
        'stock_levels': [{'name': item.name, 'current_stock': int(item.current_stock), 'threshold': int(item.threshold)} for item in stock_level_data]
    })

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    """Edit user route."""
    log_user_activity(f'edited user {user_id}')
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        changes = []
        if user.name != request.form.get('name'):
            changes.append(f"Name: {user.name} -> {request.form.get('name')}")
        if user.email != request.form.get('email'):
            changes.append(f"Email: {user.email} -> {request.form.get('email')}")
        if user.role != request.form.get('role'):
            changes.append(f"Role: {user.role} -> {request.form.get('role')}")
            
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.role = request.form.get('role')
        
        db.session.commit()
        
        if changes:
            log_user_activity('DB UPDATE', format_db_action('UPDATE', 'User', user.name,
                ' | '.join(changes)))
        flash('User updated successfully', 'success')
        return redirect(url_for('users'))
    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete user route."""
    log_user_activity(f'deleted user {user_id}')
    user = User.query.get_or_404(user_id)
    user_details = f"Name: {user.name}, Email: {user.email}, Role: {user.role}"
    
    db.session.delete(user)
    db.session.commit()
    
    log_user_activity('DB DELETE', format_db_action('DELETE', 'User', user.name,
        f"Details: {user_details}"))
    flash('User deleted successfully', 'success')
    return redirect(url_for('users'))

@app.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    """Edit product route."""
    if current_user.role not in ['ADMIN', 'MANAGER', 'SUPERVISOR']:
        flash('You do not have permission to edit products.', 'error')
        return redirect(url_for('products'))

    log_user_activity(f'edited product {product_id}')
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'POST':
        try:
            # Get form data with role-based permissions
            if current_user.role == 'ADMIN':
                product.name = request.form.get('name')
                product.description = request.form.get('description')
                product.category_id = int(request.form.get('category_id'))
                
                # Validate category
                if not Category.query.get(product.category_id):
                    flash('Selected category does not exist', 'error')
                    return render_template('edit_product.html', product=product, categories=Category.query.all())

            if current_user.role in ['ADMIN', 'MANAGER']:
                quantity = int(request.form.get('quantity'))
                low_stock_threshold = int(request.form.get('low_stock_threshold'))
                
                # Validate thresholds
                if low_stock_threshold < 0:
                    flash('Low stock threshold cannot be negative', 'error')
                    return render_template('edit_product.html', product=product, categories=Category.query.all())
                    
                product.quantity = quantity
                product.low_stock_threshold = low_stock_threshold

            if current_user.role in ['ADMIN', 'MANAGER', 'SUPERVISOR']:
                price = float(request.form.get('price'))
                '''if price <= 0:
                    flash('Price must be greater than 0', 'error')
                    return render_template('edit_product.html', product=product, categories=Category.query.all())'''
                product.price = price

            changes = []
            if current_user.role == 'ADMIN':
                if product.name != request.form.get('name'):
                    changes.append(f"Name: {product.name} -> {request.form.get('name')}")
                if product.description != request.form.get('description'):
                    changes.append(f"Description updated")
                if product.category_id != int(request.form.get('category_id')):
                    old_cat = Category.query.get(product.category_id).name
                    new_cat = Category.query.get(int(request.form.get('category_id'))).name
                    changes.append(f"Category: {old_cat} -> {new_cat}")

            if current_user.role in ['ADMIN', 'MANAGER']:
                if 'quantity' in locals() and product.quantity != quantity:
                    changes.append(f"Quantity: {product.quantity} -> {quantity}")
                if product.low_stock_threshold != int(request.form.get('low_stock_threshold')):
                    old_threshold = product.low_stock_threshold
                    new_threshold = int(request.form.get('low_stock_threshold'))
                    changes.append(f"Low Stock Threshold: {old_threshold} -> {new_threshold}")

            if current_user.role in ['ADMIN', 'MANAGER', 'SUPERVISOR']:
                if product.price != float(request.form.get('price')):
                    changes.append(f"Price: ₹{product.price} -> ₹{float(request.form.get('price'))}")

            # Apply all changes
            if current_user.role == 'ADMIN':
                product.name = request.form.get('name')
                product.description = request.form.get('description')
                product.category_id = int(request.form.get('category_id'))

            if current_user.role in ['ADMIN', 'MANAGER']:
                product.quantity = quantity
                product.low_stock_threshold = int(request.form.get('low_stock_threshold'))

            if current_user.role in ['ADMIN', 'MANAGER', 'SUPERVISOR']:
                product.price = float(request.form.get('price'))

            db.session.commit()
            
            if changes:
                log_user_activity('DB UPDATE', format_db_action('UPDATE', 'Product', product.name, 
                    ' | '.join(changes)))
            flash('Product updated successfully', 'success')
            return redirect(url_for('products'))
            
        except ValueError as e:
            flash(f'Invalid input values: {str(e)}', 'error')
            return render_template('edit_product.html', product=product, categories=Category.query.all())
            
    categories = Category.query.all()
    return render_template('edit_product.html', product=product, categories=categories)

@app.route('/products/delete/<int:product_id>', methods=['POST'])
@supervisor_required

def delete_product(product_id):
    """Delete product route."""
    log_user_activity(f'deleted product {product_id}')
    product = Product.query.get_or_404(product_id)

    # Check for related records in OrderItem and BusPart
    related_order_items = OrderItem.query.filter_by(product_id=product_id).all()
    related_bus_parts = BusPart.query.filter_by(product_id=product_id).all()

    # Delete related records if they exist
    for item in related_order_items:
        db.session.delete(item)

    for part in related_bus_parts:
        db.session.delete(part)

    # Now delete the product
    product_name = product.name
    db.session.delete(product)
    db.session.commit()
    log_user_activity('DB DELETE', format_db_action('DELETE', 'Product', product_name, 
        f"Cascade: {len(related_order_items)} orders, {len(related_bus_parts)} bus parts"))
    flash('Product and related records deleted successfully', 'success')
    return redirect(url_for('products'))

@app.route('/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@manager_required
def edit_category(category_id):
    """Edit category route."""
    log_user_activity(f'edited category {category_id}')
    category = Category.query.get_or_404(category_id)
    if request.method == 'POST':
        changes = []
        if category.name != request.form.get('name'):
            changes.append(f"Name: {category.name} -> {request.form.get('name')}")
        if category.description != request.form.get('description'):
            changes.append(f"Description updated")
            
        category.name = request.form.get('name')
        category.description = request.form.get('description')
        db.session.commit()
        
        if changes:
            log_user_activity('DB UPDATE', format_db_action('UPDATE', 'Category', category.name,
                ' | '.join(changes)))
        flash('Category updated successfully', 'success')
        return redirect(url_for('categories'))
    return render_template('edit_category.html', category=category)

@app.route('/categories/delete/<int:category_id>', methods=['POST'])
@manager_required
def delete_category(category_id):
    """Delete category route."""
    log_user_activity(f'deleted category {category_id}')
    category = Category.query.get_or_404(category_id)

    # Get details before deletion
    category_name = category.name
    products_detail = [f"{p.name} (Qty: {p.quantity})" for p in category.products]
    num_products = len(category.products)
    
    # Delete associated products
    for product in category.products:
        db.session.delete(product)

    db.session.delete(category)
    db.session.commit()
    
    log_user_activity('DB DELETE', format_db_action('DELETE', 'Category', category_name, 
        f"Deleted {num_products} products: {', '.join(products_detail)}"))
    flash('Category and associated products deleted successfully', 'success')
    return redirect(url_for('categories'))

@app.route('/user-activity')
@admin_required
def user_activity():
    """User activity route with pagination, sorting and search."""
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    user_id = request.args.get('user_id', 'all')
    sort_by = request.args.get('sort_by', 'timestamp')
    order = request.args.get('order', 'desc')

    # Base query
    query = UserActivity.query.join(User)

    # Apply user filter if provided and not "all"
    if user_id and user_id != 'all':
        try:
            user_id_int = int(user_id)
            query = query.filter(UserActivity.user_id == user_id_int)
        except ValueError:
            user_id = 'all'

    # Apply search if provided
    if search:
        query = query.filter(
            db.or_(
                User.name.ilike(f'%{search}%'),
                UserActivity.action.ilike(f'%{search}%')
            )
        )

    # Apply sorting
    if sort_by == 'username':
        if order == 'asc':
            query = query.order_by(User.name.asc())
        else:
            query = query.order_by(User.name.desc())
    elif sort_by == 'action':
        if order == 'asc':
            query = query.order_by(UserActivity.action.asc())
        else:
            query = query.order_by(UserActivity.action.desc())
    else:  # Default sort by timestamp
        if order == 'asc':
            query = query.order_by(UserActivity.timestamp.asc())
        else:
            query = query.order_by(UserActivity.timestamp.desc())

    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    activities = pagination.items

    # Get all users for the filter dropdown
    users = User.query.all()

    return render_template(
        'user_activity.html',
        activities=activities,
        pagination=pagination,
        users=users,
        search=search,
        sort_by=sort_by,
        order=order
    )



@app.route('/buses', methods=['GET'])
@login_required
def buses():
    """View all buses."""
    log_user_activity('visited buses')
    buses = Bus.query.all()
    return render_template('buses.html', buses=buses)

@app.route('/buses/add', methods=['GET', 'POST'])
@login_required
def add_bus():
    """Add a new bus."""
    if request.method == 'POST':
        try:
            bus_number = request.form.get('bus_number')  # Get the bus number
            bus_number_plate = request.form.get('bus_number_plate')  # Get the bus number plate
            manufacturer = request.form.get('manufacturer')  # Get the manufacturer
            manufacturer_date = request.form.get('manufacturer_date')  # Get the manufacturer date
            bought_date = request.form.get('bought_date')  # Get the bought date

            # Check for duplicate bus number or number plate
            existing_bus = Bus.query.filter(
                (Bus.bus_number == bus_number) | 
                (Bus.bus_number_plate == bus_number_plate)
            ).first()
            if existing_bus:
                if existing_bus.bus_number == bus_number:
                    flash('A bus with this number already exists', 'error')
                else:
                    flash('A bus with this number plate already exists', 'error')
                return redirect(url_for('add_bus'))

            # Automatically set name in format: bus_number_plate(bus_number)
            name = f"{bus_number_plate}({bus_number})"
            
            # Create description from all available data
            description = f"Bus Registration: {bus_number}, Plate: {bus_number_plate}, Manufacturer: {manufacturer}, Manufactured: {manufacturer_date}, Purchased: {bought_date}"

            # Convert dates and validate
            mfg_date = datetime.strptime(manufacturer_date, '%Y-%m-%d')
            purchase_date = datetime.strptime(bought_date, '%Y-%m-%d')
            
            if purchase_date < mfg_date:
                flash('Purchase date cannot be earlier than manufacture date', 'error')
                return redirect(url_for('add_bus'))

            # Create a new Bus instance with all required fields
            bus = Bus(
                name=name,
                description=description,
                bus_number=bus_number,
                bus_number_plate=bus_number_plate,
                manufacturer=manufacturer,
                manufacturer_date=mfg_date,
                bought_date=purchase_date
            )
            
            db.session.add(bus)
            db.session.commit()
            
            log_user_activity('DB CREATE', format_db_action('CREATE', 'Bus', name, 
                f"Number: {bus_number}, Plate: {bus_number_plate}"))
            flash('Bus added successfully', 'success')
            return redirect(url_for('buses'))
            
        except ValueError as e:
            flash(f'Invalid date format: {str(e)}', 'error')
            return redirect(url_for('add_bus'))
    
    return render_template('add_bus.html')

@app.route('/buses/edit/<int:bus_id>', methods=['GET', 'POST'])
@login_required
def edit_bus(bus_id):
    """Edit an existing bus."""
    bus = Bus.query.get_or_404(bus_id)
    if request.method == 'POST':
        try:
            # Store old values for logging
            old_number = bus.bus_number
            old_plate = bus.bus_number_plate
            old_manufacturer = bus.manufacturer
            old_mfg_date = bus.manufacturer_date
            old_bought_date = bus.bought_date

            # Get form data
            bus_number = request.form.get('bus_number')
            bus_number_plate = request.form.get('bus_number_plate')
            manufacturer = request.form.get('manufacturer')
            manufacturer_date = request.form.get('manufacturer_date')
            bought_date = request.form.get('bought_date')

            # Track changes
            changes = []
            if old_number != bus_number:
                changes.append(f"Number: {old_number} -> {bus_number}")
            if old_plate != bus_number_plate:
                changes.append(f"Plate: {old_plate} -> {bus_number_plate}")
            if old_manufacturer != manufacturer:
                changes.append(f"Manufacturer: {old_manufacturer} -> {manufacturer}")

            # Update fields
            bus.bus_number = bus_number
            bus.bus_number_plate = bus_number_plate
            bus.manufacturer = manufacturer

            # Automatically set name in format: bus_number_plate(bus_number)
            bus.name = f"{bus_number_plate}({bus_number})"
            
            # Create description from all available data
            bus.description = f"Bus Registration: {bus_number}, Plate: {bus_number_plate}, Manufacturer: {manufacturer}, Manufactured: {manufacturer_date}, Purchased: {bought_date}"

            # Handle dates with proper validation
            if manufacturer_date:
                new_mfg_date = datetime.strptime(manufacturer_date, '%Y-%m-%d')
                if old_mfg_date != new_mfg_date:
                    changes.append(f"Manufacture Date: {old_mfg_date.strftime('%Y-%m-%d')} -> {new_mfg_date.strftime('%Y-%m-%d')}")
                bus.manufacturer_date = new_mfg_date

            if bought_date:
                new_bought_date = datetime.strptime(bought_date, '%Y-%m-%d')
                if old_bought_date != new_bought_date:
                    changes.append(f"Purchase Date: {old_bought_date.strftime('%Y-%m-%d')} -> {new_bought_date.strftime('%Y-%m-%d')}")
                bus.bought_date = new_bought_date
                
                # Validate dates
                if bus.bought_date < bus.manufacturer_date:
                    flash('Bought date cannot be earlier than manufacturer date', 'error')
                    return render_template('edit_bus.html', bus=bus)
            
            db.session.commit()
            
            if changes:
                log_user_activity('DB UPDATE', format_db_action('UPDATE', 'Bus', bus.name,
                    ' | '.join(changes)))
            flash('Bus details updated successfully', 'success')
            return redirect(url_for('manage_buses'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating bus: {str(e)}', 'error')
            return render_template('edit_bus.html', bus=bus)
    
    return render_template('edit_bus.html', bus=bus)

@app.route('/buses/delete/<int:bus_id>', methods=['POST'])
@login_required
def delete_bus(bus_id):
    """Delete a bus."""
    bus = Bus.query.get_or_404(bus_id)

    # Delete related BusPart records
    related_bus_parts = BusPart.query.filter_by(bus_id=bus_id).all()
    for part in related_bus_parts:
        db.session.delete(part)

    bus_name = bus.name
    num_parts = len(related_bus_parts)
    db.session.delete(bus)
    db.session.commit()
    
    log_user_activity('DB DELETE', format_db_action('DELETE', 'Bus', bus_name, 
        f"Cascade: {num_parts} parts"))
    flash('Bus deleted successfully', 'success')
    return redirect(url_for('buses'))


class BusPart(db.Model):
    """Define the BusPart model to associate products with buses."""
    id = db.Column(db.Integer, primary_key=True)
    bus_id = db.Column(db.Integer, db.ForeignKey('bus.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)  # Keep only product_id
    quantity = db.Column(db.Integer, nullable=False)
    time = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by = db.Column(db.String(255), nullable=True)  # Add this line
    bus = db.relationship('Bus', backref='bus_parts')
    product = db.relationship('Product', backref='bus_parts')

@app.route('/assign-parts', methods=['GET', 'POST'])
#@supervisor_required
@login_required
def assign_parts():
    """Assign products to a bus."""
    buses = Bus.query.all()
    products = Product.query.all()  # Fetch products instead of parts

    if request.method == 'POST':
        bus_id = request.form.get('bus_id')
        product_id = request.form.get('part_id')  # Use product_id from the form
        quantity = int(request.form.get('quantity'))

        # Fetch the bus and product
        bus = Bus.query.get(bus_id)
        product = db.session.get(Product, product_id)

        if product is None:
            flash('Product not found.', 'error')
            return redirect(url_for('assign_parts'))

        if product.quantity < quantity:
            flash('Insufficient quantity available for this product.', 'error')
            return redirect(url_for('assign_parts'))

        # Create a new BusPart entry
        bus_part = BusPart(bus_id=bus_id, product_id=product_id, quantity=quantity, assigned_by=current_user.role)
        db.session.add(bus_part)

        # Update the product quantity
        old_quantity = product.quantity
        product.quantity -= quantity

        db.session.commit()
        
        log_user_activity('DB CREATE', format_db_action('CREATE', 'BusPart Assignment', f"{product.name} to {bus.name}",
            f"Assigned Qty: {quantity} | Product Stock: {old_quantity} -> {product.quantity}"))
        flash('Product assigned to bus successfully.', 'success')
        return redirect(url_for('assign_parts'))

    return render_template('assign_parts.html', buses=buses, products=products)

@app.route('/assigned-to')
@login_required
def assigned_to():
    """View assigned parts to buses."""
    try:
        # Modified query to ensure all fields are properly selected
        assignments = db.session.query(
            BusPart.bus_id,
            Bus.bus_number.label('bus_number'),
            Bus.bus_number_plate.label('bus_number_plate'),
            BusPart.product_id,
            Product.name.label('product_name'),
            BusPart.quantity,
            BusPart.assigned_by,
            BusPart.time.label('date_assigned')
        ).join(
            Bus, Bus.id == BusPart.bus_id  # Explicit join condition
        ).join(
            Product, Product.id == BusPart.product_id  # Explicit join condition
        ).order_by(BusPart.time.desc()).all()

        print("Assignments Retrieved:", assignments)  # Debugging output
        
        # Convert query results to dictionaries for easier template handling
        formatted_assignments = []
        for assignment in assignments:
            formatted_assignments.append({
                'bus_number': f"{assignment.bus_number_plate}({assignment.bus_number})",
                'product_name': assignment.product_name,
                'quantity': assignment.quantity,
                'assigned_by': assignment.assigned_by,
                'date_assigned': assignment.date_assigned
            })

        return render_template('assigned_to.html', assignments=formatted_assignments)
    except Exception as e:
        print(f"Error in assigned_to route: {str(e)}")  # Debug logging
        flash('Error loading assignments data', 'error')
        return render_template('assigned_to.html', assignments=[])


@app.route('/manage-buses', methods=['GET'])
@login_required
@admin_required
def manage_buses():
    """View all buses in the management panel."""
    buses = Bus.query.all()  # Fetch all buses from the database
    return render_template('manage_buses.html', buses=buses)


@app.route('/bulk-upload')
@login_required
def bulk_upload_page():
    """Show bulk upload page."""
    return render_template('bulk_upload.html')

@app.route('/bulk-upload/<type>', methods=['POST'])
@login_required
def bulk_upload(type):
    """Handle bulk upload of data."""
    if 'file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('bulk_upload_page'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('bulk_upload_page'))
    
    if not file.filename.endswith('.csv'):
        flash('Only CSV files are allowed', 'error')
        return redirect(url_for('bulk_upload_page'))
    
    try:
        # Read CSV file
        stream = StringIO(file.stream.read().decode("UTF8"), newline=None)
        df = pd.read_csv(stream)
        
        if type == 'bus':
            required_columns = ['BUS NO', 'Registration NO', 'MAKER', 'MODEL', 'YEAR OF PURCHASE']
            if not all(col in df.columns for col in required_columns):
                flash('Missing required columns for bus data', 'error')
                return redirect(url_for('bulk_upload_page'))
            
            for _, row in df.iterrows():
                # Check for duplicate bus number or plate
                existing_bus = Bus.query.filter(
                    (Bus.bus_number == str(row['BUS NO'])) | 
                    (Bus.bus_number_plate == row['Registration NO'])
                ).first()
                
                if existing_bus:
                    if existing_bus.bus_number == str(row['BUS NO']):
                        flash(f'Bus number {row["BUS NO"]} already exists', 'error')
                    else:
                        flash(f'Bus number plate {row["Registration NO"]} already exists', 'error')
                    continue
                
                # Convert year to date format
                mfg_date = f"{row['MODEL']}-01-01"
                bought_date = f"{row['YEAR OF PURCHASE']}-01-01"
                
                # Validate dates
                mfg_date_obj = datetime.strptime(mfg_date, '%Y-%m-%d')
                bought_date_obj = datetime.strptime(bought_date, '%Y-%m-%d')
                
                if bought_date_obj < mfg_date_obj:
                    flash(f'Bus {row["BUS NO"]}: Purchase date cannot be earlier than manufacture date', 'error')
                    continue
                
                # Create bus with the correct name format
                name = f"{row['Registration NO']}({row['BUS NO']})"
                description = f"Bus Registration: {row['BUS NO']}, Plate: {row['Registration NO']}, Manufacturer: {row['MAKER']}, Model: {row['MODEL']}, Year: {row['YEAR OF PURCHASE']}"
                
                bus = Bus(
                    name=name,
                    description=description,
                    bus_number=str(row['BUS NO']),
                    bus_number_plate=row['Registration NO'],
                    manufacturer=row['MAKER'],
                    manufacturer_date=mfg_date_obj,
                    bought_date=bought_date_obj
                )
                db.session.add(bus)
            
        elif type == 'product':
            required_columns = ['name', 'description', 'quantity', 'price', 'category', 'low_stock_threshold']
            if not all(col in df.columns for col in required_columns):
                flash('Missing required columns for product data', 'error')
                return redirect(url_for('bulk_upload_page'))
            
            for _, row in df.iterrows():
                try:
                    # Validate numeric values
                    quantity = int(row['quantity'])
                    price = float(row['price'])
                    low_stock_threshold = int(row['low_stock_threshold'])
                    
                    if quantity < 0:
                        flash(f'Product {row["name"]}: Quantity cannot be negative', 'error')
                        continue
                    if price <= 0:
                        flash(f'Product {row["name"]}: Price must be greater than 0', 'error')
                        continue
                    if low_stock_threshold < 0:
                        flash(f'Product {row["name"]}: Low stock threshold cannot be negative', 'error')
                        continue
                        
                    # Get category by name
                    category = Category.query.filter_by(name=row['category']).first()
                    if not category:
                        flash(f'Product {row["name"]}: Category "{row["category"]}" does not exist', 'error')
                        continue
                    
                    # Check for duplicate product name
                    if Product.query.filter_by(name=row['name']).first():
                        flash(f'Product {row["name"]} already exists', 'error')
                        continue
                    
                    product = Product(
                        name=row['name'],
                        description=row['description'],
                        quantity=quantity,
                        price=price,
                        category_id=category.id,
                        low_stock_threshold=low_stock_threshold
                    )
                    db.session.add(product)
                except ValueError:
                    flash(f'Product {row["name"]}: Invalid numeric values', 'error')
                    continue
                
        elif type == 'category':
            required_columns = ['name', 'description']
            if not all(col in df.columns for col in required_columns):
                flash('Missing required columns for category data', 'error')
                return redirect(url_for('bulk_upload_page'))
            
            for _, row in df.iterrows():
                # Check for duplicate category name
                if Category.query.filter_by(name=row['name']).first():
                    flash(f'Category {row["name"]} already exists', 'error')
                    continue
                    
                category = Category(
                    name=row['name'],
                    description=row['description']
                )
                db.session.add(category)
        
        db.session.commit()
        flash(f'Successfully uploaded {len(df)} {type}s', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error uploading data: {str(e)}', 'error')
    
    return redirect(url_for('bulk_upload_page'))

@app.route('/download-sample/<type>')
@login_required
def download_sample(type):
    """Download sample CSV file."""
    try:
        if type in ['bus', 'product', 'category']:
            return send_file(
                f'static/samples/{type}_sample.csv',
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'{type}_sample.csv'
            )
    except Exception as e:
        flash(f'Error downloading sample file: {str(e)}', 'error')
    
    return redirect(url_for('bulk_upload_page'))

@app.route('/products/<int:category_id>', methods=['GET'])
def get_products_by_category(category_id):
    """Fetch products for a specific category."""
    products = Product.query.filter_by(category_id=category_id).all()  # Adjust based on your ORM
    return jsonify({'products': [{'id': product.id, 'name': product.name} for product in products]})

@app.route('/fuel-consumption', methods=['GET'])
@login_required
def fuel_consumption():
    """Fuel consumption management page with backend search, filter and pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search = request.args.get('search', '')
    filter_type = request.args.get('filter', 'all')
    sort_by = request.args.get('sort', 'bus')
    
    # Base query
    query = Bus.query

    # Apply search if provided
    if search:
        search_terms = search.split()
        conditions = []
        for term in search_terms:
            conditions.append(
                db.or_(
                    Bus.bus_number.ilike(f'%{term}%'),
                    Bus.bus_number_plate.ilike(f'%{term}%')
                )
            )
        query = query.filter(db.and_(*conditions))

    # Apply sorting
    if sort_by == 'consumption':
        # Subquery to get total consumption for each bus
        consumption_subq = db.session.query(
            Fuel.bus_id,
            db.func.sum(Fuel.fuel_amount).label('total_consumption')
        ).group_by(Fuel.bus_id).subquery()
        
        query = query.outerjoin(
            consumption_subq,
            Bus.id == consumption_subq.c.bus_id
        ).order_by(db.desc(consumption_subq.c.total_consumption))
    elif sort_by == 'mileage':
        # We'll sort by the latest mileage calculation
        query = query.order_by(Bus.id.desc())  # Default to newest buses first
    else:  # sort by bus number
        query = query.order_by(Bus.bus_number)

    # Get paginated results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    buses = pagination.items
    total_pages = pagination.pages
    
    # Calculate consumption and mileage for each bus
    for bus in buses:
        fuel_records = Fuel.query.filter_by(bus_id=bus.id).order_by(Fuel.date.desc()).all()
        
        # Calculate total fuel consumption
        bus.total_fuel_consumption = sum(record.fuel_amount for record in fuel_records)
        
        # Calculate current mileage (km/L) from the last two records
        if len(fuel_records) >= 2:
            latest_record = fuel_records[0]
            prev_record = fuel_records[1]
            distance = latest_record.reading - prev_record.reading
            bus.current_mileage = distance / latest_record.fuel_amount if latest_record.fuel_amount > 0 else 0
        else:
            bus.current_mileage = 0
            
        # Apply efficiency filter after calculations
        if filter_type != 'all':
            if filter_type == 'efficient' and bus.current_mileage <= 15:
                buses.remove(bus)
            elif filter_type == 'normal' and (bus.current_mileage < 10 or bus.current_mileage > 15):
                buses.remove(bus)
            elif filter_type == 'inefficient' and bus.current_mileage >= 10:
                buses.remove(bus)
    
    return render_template('fuel_consumption.html', 
                         buses=buses,
                         page=page,
                         has_next=pagination.has_next,
                         total_pages=total_pages,
                         search=search,
                         filter=filter_type,
                         sort=sort_by)


@app.route('/fuel-logs')
@login_required
def fuel_logs():
    """View all fuel consumption logs with pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get paginated records ordered by date ascending (oldest to newest)
    pagination = Fuel.query.order_by(Fuel.date.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    fuel_logs = pagination.items
    has_next = pagination.has_next
    
    return render_template('fuel_logs.html', 
                         fuel_logs=fuel_logs,
                         page=page,
                         has_next=has_next)




@app.route('/add-fuel-consumption', methods=['POST'])
@login_required
def add_fuel_consumption():
    """Add new fuel consumption record."""
    try:
        bus_id = request.form.get('bus_id')
        fuel_amount = float(request.form.get('fuel_amount'))
        reading = float(request.form.get('reading'))
        date_str = request.form.get('date')
        
        if not all([bus_id, fuel_amount, reading, date_str]):
            flash('All fields are required', 'error')
            return redirect(url_for('fuel_consumption'))
        
        date = datetime.strptime(date_str, '%Y-%m-%d')
        
        # Get the last fuel record for this bus to calculate distance traveled
        last_record = Fuel.query.filter_by(bus_id=bus_id).order_by(Fuel.date.desc()).first()
        
        # Validate that new reading is greater than the last reading
        if last_record and reading <= last_record.reading:
            flash(f'New reading ({reading} km) must be greater than the last reading ({last_record.reading} km)', 'error')
            return redirect(url_for('fuel_consumption'))
            
        fuel_record = Fuel(
            bus_id=bus_id,
            fuel_amount=fuel_amount,
            reading=reading,
            date=date,
            created_by=current_user.id
        )
        
        # Get bus details for logging
        bus = Bus.query.get(bus_id)
        
        db.session.add(fuel_record)
        db.session.commit()
        
        # Calculate and display mileage if there's a previous record
        if last_record:
            distance = reading - last_record.reading
            mileage = distance / fuel_amount if fuel_amount > 0 else 0
            log_user_activity('DB CREATE', format_db_action('CREATE', 'Fuel Record', f"Bus {bus.name}",
                f"Amount: {fuel_amount}L, Distance: {distance:.2f}km, Mileage: {mileage:.2f}km/L"))
            flash(f'Fuel consumption record added successfully. Distance: {distance:.2f} km, Mileage: {mileage:.2f} km/L', 'success')
        else:
            log_user_activity('DB CREATE', format_db_action('CREATE', 'Fuel Record', f"Bus {bus.name}",
                f"Amount: {fuel_amount}L, Initial Reading: {reading}km"))
            flash('First fuel consumption record added successfully', 'success')
            
        return redirect(url_for('fuel_consumption'))
        
    except ValueError as e:
        flash(f'Invalid input: {str(e)}', 'error')
        return redirect(url_for('fuel_consumption'))

@app.route('/fuel-reports')
@login_required
def fuel_reports():
    """Fuel reports route with comprehensive metrics."""
    # Get all buses with their fuel data
    buses = Bus.query.all()
    
    # Calculate metrics for each bus
    bus_reports = []
    for bus in buses:
        fuel_records = Fuel.query.filter_by(bus_id=bus.id).order_by(Fuel.date.desc()).all()
        
        # Calculate total fuel consumption
        total_fuel = sum(record.fuel_amount for record in fuel_records)
        
        # Calculate total distance traveled
        total_distance = fuel_records[0].reading - fuel_records[-1].reading if len(fuel_records) > 1 else 0
        
        # Calculate average mileage
        avg_mileage = total_distance / total_fuel if total_fuel > 0 else 0
        
        # Get maintenance status
        maintenance_status = 'Good'  # Placeholder, implement actual logic
        
        bus_reports.append({
            'bus': bus,
            'total_fuel': total_fuel,
            'total_distance': total_distance,
            'avg_mileage': avg_mileage,
            'maintenance_status': maintenance_status
        })
    
    # Calculate fleet-wide metrics
    total_fleet_fuel = sum(report['total_fuel'] for report in bus_reports)
    total_fleet_distance = sum(report['total_distance'] for report in bus_reports)
    avg_fleet_mileage = total_fleet_distance / total_fleet_fuel if total_fleet_fuel > 0 else 0
    
    return render_template('fuel_reports.html',
                         bus_reports=bus_reports,
                         total_fleet_fuel=total_fleet_fuel,
                         total_fleet_distance=total_fleet_distance,
                         avg_fleet_mileage=avg_fleet_mileage)

@app.route('/fuel-history/<int:bus_id>')
@login_required
def fuel_history(bus_id):

    """Get fuel consumption history for a specific bus."""
    records = Fuel.query.filter_by(bus_id=bus_id).order_by(Fuel.date.desc()).all()
    
    history = []
    for i, record in enumerate(records):
        entry = {
            'date': record.date.strftime('%Y-%m-%d %H:%M'),
            'fuel_amount': record.fuel_amount,
            'reading': record.reading
        }
        
        # Calculate mileage if there's a next record (previous chronologically)
        if i < len(records) - 1:
            next_record = records[i + 1]
            distance = record.reading - next_record.reading
            mileage = distance / record.fuel_amount if record.fuel_amount > 0 else 0
            entry['distance'] = f"{distance:.2f} km"
            entry['mileage'] = f"{mileage:.2f} km/L"
        else:
            entry['distance'] = "N/A"
            entry['mileage'] = "N/A"
            
        history.append(entry)
    
    return jsonify({'history': history})


# API endpoint for fuel report data
@app.route('/api/fuel-report-data')
@login_required
def fuel_report_data():
    """API endpoint for fuel report data."""
    buses = Bus.query.all()
    report_data = []
    
    for bus in buses:
        fuel_records = Fuel.query.filter_by(bus_id=bus.id).order_by(Fuel.date.asc()).all()
        
        if len(fuel_records) > 1:
            # Calculate mileage for each period
            mileage_data = []
            for i in range(1, len(fuel_records)):
                distance = fuel_records[i].reading - fuel_records[i-1].reading
                fuel_used = fuel_records[i].fuel_amount
                mileage = distance / fuel_used if fuel_used > 0 else 0
                mileage_data.append({
                    'date': fuel_records[i].date.strftime('%Y-%m-%d'),
                    'mileage': mileage
                })
            
            report_data.append({
                'bus_id': bus.id,
                'bus_name': f"{bus.bus_number_plate}({bus.bus_number})",
                'mileage_data': mileage_data
            })
    
    return jsonify(report_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True,host="0.0.0.0", port=5000)
