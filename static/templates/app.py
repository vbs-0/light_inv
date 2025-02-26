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
'''
@app.route('/user-activity')
@admin_required
def user_activity():
    """User activity route with pagination, sorting and search."""
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'timestamp')
    order = request.args.get('order', 'desc')

    # Base query
    query = UserActivity.query.join(User)

    # Apply search if provided
    if search:
        query = query.filter(
            db.or_(
                User.name.ilike(f'%{search}%'),
                UserActivity.action.ilike(f'%{search}%')
            )
        )

    # Apply sorting
    if sort_by == 'user':
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

    return render_template(
        'user_activity.html',
        activities=activities,
        pagination=pagination,
        search=search,
        sort_by=sort_by,
        order=order
    )
'''

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

def log_user_activity(action):
    """Function to log user activity."""
    activity = UserActivity(user_id=current_user.id, action=action)
    db.session.add(activity)
    db.session.commit()

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
        
        flash('User added successfully')
        log_user_activity(f'added user {user.name}')
        return redirect(url_for('users'))
    
    return render_template('add_user.html')

@app.route('/products')
@login_required
def products():
    """Products route."""
    log_user_activity('visited products')
    products = Product.query.all()
    categories = Category.query.all()
    return render_template('products.html', products=products, categories=categories)

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
                product.quantity += quantity
                flash('Product quantity updated successfully')
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
            flash('New product added successfully')
        except ValueError:
            flash('Invalid input values', 'error')
            return redirect(url_for('products'))
    
    db.session.commit()
    return redirect(url_for('products'))

@app.route('/categories')
@login_required
def categories():
    """Categories route."""
    log_user_activity('visited categories')
    categories = Category.query.all()
    return render_template('categories.html', categories=categories)

@app.route('/categories/add', methods=['POST'])
@manager_required
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
    
    flash('Category added successfully')
    log_user_activity(f'added category {category.name}')
    return redirect(url_for('categories'))

@app.route('/orders')
@login_required
def orders():
    """Orders route."""
    log_user_activity('visited orders')
    
    # Get filter parameters from request
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')

    if current_user.role in ['ADMIN','SUPERVISOR', 'MANAGER']:
        # Fetch all orders and sort by order ID in descending order
        orders = Order.query.join(User).add_columns(User.name, User.role).order_by(Order.id.desc()).all()
    else:
        # Fetch user's orders and sort by order ID in descending order
        orders = Order.query.filter_by(user_id=current_user.id).join(User).add_columns(User.name, User.role).order_by(Order.id.desc()).all()
    
    # Apply filter
    filtered_orders = []
    for order, user_name, user_role in orders:
        if (search.lower() in str(order.id) or 
            search.lower() in user_name.lower() or 
            search.lower() in user_role.lower() or 
            search.lower() in order.status.lower()):
            if status == 'all' or status.upper() == order.status:
                filtered_orders.append((order, user_name, user_role))
    
    products = Product.query.all()
    return render_template('orders.html', orders=filtered_orders, products=products, search=search, status=status)

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
            
            # Prevent negative quantities
            if quantity < 1:
                flash('Quantity must be at least 1 for all items.', 'error')
                return redirect(url_for('orders'))

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

    db.session.add(order)
    db.session.commit()
    log_user_activity(f'created order with {len(order.items)} items')
    
    flash('Order created successfully')
    return redirect(url_for('orders'))


@app.route('/orders/<int:order_id>/update-status', methods=['POST'])
@manager_required
def update_order_status(order_id):
    """Update order status route."""
    order = Order.query.get_or_404(order_id)
    status = request.form.get('status')
    
    if status in ['PENDING', 'APPROVED', 'REJECTED', 'COMPLETED']:
        order.status = status
        db.session.commit()
        log_user_activity(f'updated order {order_id} status to {status}')
        flash('Order status updated successfully')
    
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
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.role = request.form.get('role')
        db.session.commit()
        flash('User updated successfully')
        return redirect(url_for('users'))
    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete user route."""
    log_user_activity(f'deleted user {user_id}')
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully')
    return redirect(url_for('users'))

@app.route('/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
#@manager_required
#@admin_required
#@supervisor_required

def edit_product(product_id):
    """Edit product route."""
    log_user_activity(f'edited product {product_id}')
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        try:
            quantity = int(request.form.get('quantity'))
            price = float(request.form.get('price'))
            low_stock_threshold = int(request.form.get('low_stock_threshold'))
            category_id = int(request.form.get('category_id'))
            
            # Validate inputs
            if quantity < 0:
                flash('Quantity cannot be negative', 'error')
                return render_template('edit_product.html', product=product, categories=Category.query.all())
            if price <= 0:
                flash('Price must be greater than 0', 'error')
                return render_template('edit_product.html', product=product, categories=Category.query.all())
            if low_stock_threshold < 0:
                flash('Low stock threshold cannot be negative', 'error')
                return render_template('edit_product.html', product=product, categories=Category.query.all())
            
            # Check if category exists
            if not Category.query.get(category_id):
                flash('Selected category does not exist', 'error')
                return render_template('edit_product.html', product=product, categories=Category.query.all())
            
            product.name = request.form.get('name')
            product.description = request.form.get('description')
            product.quantity = quantity
            product.price = price
            product.low_stock_threshold = low_stock_threshold
            product.category_id = category_id
            
            db.session.commit()
            flash('Product updated successfully')
            return redirect(url_for('products'))
            
        except ValueError:
            flash('Invalid numeric values', 'error')
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
    db.session.delete(product)
    db.session.commit()
    flash('Product and related records deleted successfully')
    return redirect(url_for('products'))

@app.route('/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@manager_required
def edit_category(category_id):
    """Edit category route."""
    log_user_activity(f'edited category {category_id}')
    category = Category.query.get_or_404(category_id)
    if request.method == 'POST':
        category.name = request.form.get('name')
        category.description = request.form.get('description')
        db.session.commit()
        flash('Category updated successfully')
        return redirect(url_for('categories'))
    return render_template('edit_category.html', category=category)

@app.route('/categories/delete/<int:category_id>', methods=['POST'])
@manager_required
def delete_category(category_id):
    """Delete category route."""
    log_user_activity(f'deleted category {category_id}')
    category = Category.query.get_or_404(category_id)

    # Delete associated products
    for product in category.products:
        db.session.delete(product)

    db.session.delete(category)
    db.session.commit()
    flash('Category and associated products deleted successfully')
    return redirect(url_for('categories'))

@app.route('/user-activity')
@admin_required
def user_activity():
    """User activity route with pagination, sorting and search."""
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'timestamp')
    order = request.args.get('order', 'desc')

    # Base query
    query = UserActivity.query.join(User)

    # Apply search if provided
    if search:
        query = query.filter(
            db.or_(
                User.name.ilike(f'%{search}%'),
                UserActivity.action.ilike(f'%{search}%')
            )
        )

    # Apply sorting
    if sort_by == 'user':
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

    return render_template(
        'user_activity.html',
        activities=activities,
        pagination=pagination,
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
            
            flash('Bus added successfully')
            log_user_activity(f'added bus {bus.name}')
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
            # Get form data
            bus_number = request.form.get('bus_number')
            bus_number_plate = request.form.get('bus_number_plate')
            manufacturer = request.form.get('manufacturer')
            manufacturer_date = request.form.get('manufacturer_date')
            bought_date = request.form.get('bought_date')

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
                bus.manufacturer_date = datetime.strptime(manufacturer_date, '%Y-%m-%d')
            if bought_date:
                bus.bought_date = datetime.strptime(bought_date, '%Y-%m-%d')
                
                # Validate dates
                if bus.bought_date < bus.manufacturer_date:
                    flash('Bought date cannot be earlier than manufacturer date', 'error')
                    return render_template('edit_bus.html', bus=bus)
            
            db.session.commit()
            flash('Bus details updated successfully', 'success')
            log_user_activity(f'edited bus {bus.name}')
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

    db.session.delete(bus)
    db.session.commit()
    
    flash('Bus deleted successfully')
    log_user_activity(f'deleted bus {bus.name}')
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
        quantity = request.form.get('quantity')

        # Debugging output
        print(f"Bus ID: {bus_id}, Product ID: {product_id}, Quantity: {quantity}")

        # Fetch the product using the correct product_id
        product = db.session.get(Product, product_id)  # Updated to use product_id

        if product is None:
            flash('Product not found.', 'error')
            return redirect(url_for('assign_parts'))

        if product.quantity < int(quantity):
            flash('Insufficient quantity available for this product.', 'error')
            return redirect(url_for('assign_parts'))

        # Create a new BusPart entry
        bus_part = BusPart(bus_id=bus_id, product_id=product_id, quantity=quantity, assigned_by=current_user.role)  # Set assigned_by
        db.session.add(bus_part)

        # Update the product quantity
        product.quantity -= int(quantity)

        db.session.commit()
        flash('Product assigned to bus successfully.')
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
            required_columns = ['name', 'description', 'quantity', 'price', 'category_id', 'low_stock_threshold']
            if not all(col in df.columns for col in required_columns):
                flash('Missing required columns for product data', 'error')
                return redirect(url_for('bulk_upload_page'))
            
            for _, row in df.iterrows():
                try:
                    # Validate numeric values
                    quantity = int(row['quantity'])
                    price = float(row['price'])
                    category_id = int(row['category_id'])
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
                        
                    # Check if category exists
                    if not Category.query.get(category_id):
                        flash(f'Product {row["name"]}: Category ID {category_id} does not exist', 'error')
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
                        category_id=category_id,
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True,host="0.0.0.0", port=5000)
