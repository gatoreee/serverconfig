"""Comment."""
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import os

app = Flask(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__)) 
def getClientSecrets():
	return os.path.join(APP_ROOT, "client_secrets.json")

CLIENT_ID = json.loads(open(getClientSecrets(), 'r').read())['web'][
    'client_id']

""" Connect to Database and create DB session."""
engine = create_engine('postgresql://catalog:catalog@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = scoped_session(DBSession)

categories = (('Electrics',), ('Acoustics',), ('Basses',), ('Classicals',),
              ('Amplifiers',), ('Effects',))


def add_category(category_name):
    """Add category to DB."""
    new_category = Category(name=category_name)
    session.add(new_category)
    session.commit()
    return


# Add category if not already in DB
db_categories = session.query(Category.name).all()
for category in categories:
    if category not in db_categories:
        print "Added category: " + category[0]
        add_category(category[0])


# Show all categories
@app.route('/')
@app.route('/catalog/')
def show_catalog():
    """Show all categories."""
    latest_items = session.query(Item).all()
    return render_template('catalog.html', items=latest_items)


# Show a category's items
@app.route('/catalog/<category_name>/')
@app.route('/catalog/<category_name>/items/')
def show_items(category_name):
    """Show a category's items."""
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return render_template('catalog.html', items=items)


# Show an item
@app.route('/catalog/<category_name>/<item_name>/')
def show_item(category_name, item_name):
    """Show an item."""
    item = session.query(Item).filter_by(name=item_name).one()
    return render_template('showItem.html', item=item)


# Create a new item
@app.route('/catalog/new/', methods=['GET', 'POST'])
def new_item():
    """Create a new item."""
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(
            Category).filter_by(name=request.form['category']).one()
        new_item = Item(name=request.form['name'],
                        description=request.form['description'],
                        price=request.form['price'], category_id=category.id,
                        user_id=login_session['user_id'])
        session.add(new_item)
        session.commit()
        flash('New %s Item Successfully Created' % (new_item.name))
        return redirect(url_for('show_items', category_name=category.name))
    else:
        return render_template('newItem.html')


# Edit an item
@app.route('/catalog/<item_name>/edit/', methods=['GET', 'POST'])
def edit_item(item_name):
    """Edit an item."""
    if 'username' not in login_session:
        return redirect('/login')
    item_to_edit = session.query(Item).filter_by(name=item_name).one()
    print item_to_edit.user_id
    print login_session['user_id']
    if item_to_edit.user_id != login_session['user_id']:
        flash('User %s is not allowed to edit item %s' %
              (login_session['username'], item_to_edit.name))
        return redirect('/catalog')
    category_id = item_to_edit.category_id
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            item_to_edit.name = request.form['name']
        if request.form['description']:
            item_to_edit.description = request.form['description']
        if request.form['price']:
            item_to_edit.price = request.form['price']
        if request.form['category']:
            category = session.query(Category).filter_by(
                name=request.form['category']).one()
            item_to_edit.category_id = category.id
        session.add(item_to_edit)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('show_item', category_name=category.name,
                        item_name=item_to_edit.name))
    else:
        return render_template('editItem.html', category_name=category.name,
                               item_name=item_name, item=item_to_edit)


# Delete a menu item
@app.route('/catalog/<item_name>/delete/', methods=['GET', 'POST'])
def delete_item(item_name):
    """Delete a menu item."""
    if 'username' not in login_session:
        return redirect('/login')
    item_to_delete = session.query(Item).filter_by(name=item_name).one()
    if item_to_delete.user_id != login_session['user_id']:
        flash('User %s is not allowed to delete item %s' % (
              login_session['username'], item_to_delete.name))
        return redirect('/catalog')
    if request.method == 'POST':
        session.delete(item_to_delete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect('/catalog')
    else:
        return render_template('deleteItem.html', item=item_to_delete)


# Create anti-forgery state token
@app.route('/login')
def show_login():
    """Create anti-forgery state token."""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Validate user through google+."""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(os.path.join(APP_ROOT, "client_secrets.json"), scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = get_user_id(data["email"])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
        -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """Log user off through google+."""
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    h = httplib2.Http()
    if credentials.access_token_expired:
        credentials.refresh(h)
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token

    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        print result['status']
        print credentials.access_token_expired
        print credentials.token_expiry
        print credentials.refresh_token
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """Validate user through facebook."""
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open(os.path.join(APP_ROOT, "fb_client_secrets.json"), 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open(os.path.join(APP_ROOT, "fb_client_secrets.json"), 'r').read())['web']['app_secret']

    print "App ID: %s" % app_id
    print "App secret: %s" % app_secret
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
		app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print "Result: %s" % result
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """Log user through with facebook."""
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
          facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/disconnect')
def disconnect():
    """Disconnect based on provider."""
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('show_catalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('show_catalog'))


def create_user(login_session):
    """Creat new user."""
    new_user = User(name=login_session['username'], email=login_session[
                    'email'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    """Get user info from user id."""
    user = session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    """Get user ID from user email."""
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/catalog/json/')
@app.route('/catalog/JSON/')
def catalog_json():
    """Get JSON version of catalog."""
    items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<category_name>/json/')
@app.route('/catalog/<category_name>/JSON/')
def category_json(category_name):
    """Get JSON version of a category."""
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<category_name>/<item_name>/json/')
@app.route('/catalog/<category_name>/<item_name>/JSON')
def item_json(category_name, item_name):
    """Get JSON version of an item."""
    item = session.query(Item).filter_by(name=item_name).one()
    return jsonify(item=[item.serialize])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
