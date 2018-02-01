from catalog_db import User, Decor, Item, Base
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from flask import session as login_session
import random
import string
from flask import Flask, render_template, request, redirect, jsonify
from flask import make_response, flash, g, url_for
from flask import session as l_session
from flask.ext.httpauth import HTTPBasicAuth
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
auth = HTTPBasicAuth()
app = Flask(__name__)
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Menu Application"

# Connect to database and create session
engine = create_engine('sqlite:///catalog3.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


'''@auth.verify_password
def verify_password(username, password):
    user = session.query(User).filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True'''


# JSON endpoint for user
@app.route('/user/JSON')
def userJSON():
    user = session.query(User).all()
    return jsonify(user=[i.serialize for i in user])


# JSON endpoint for category
@app.route('/category/JSON')
def categoryJSON():
    category = session.query(Decor).all()
    return jsonify(category=[i.serialize for i in category])


# JSON endpoint for item
@app.route('/items/JSON')
def itemJSON():
    items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in items])


# JSON endpoint for decor
@app.route('/<int:decor_id>/JSON')
def decorJSON(decor_id):
    decor = session.query(Decor).filter_by(id=decor_id).first()
    items = session.query(Item).filter_by(d_id=decor.id).all()
    return jsonify(decor=decor.serialize, items=[i.serialize for i in items])


# JSON endpoint for item specific
@app.route('/<int:decor_id>/<int:item_id>/JSON')
def itemidJSON(decor_id, item_id):
    decor = session.query(Decor).filter_by(id=decor_id).first()
    item = session.query(Item).filter_by(id=item_id).first()
    return jsonify(decor=decor.serialize, item=item.serialize)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    print(access_token)
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    response, content = h.request(url, 'GET')
    result = json.loads(content.decode('utf-8'))
    print(result)
    # result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

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
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    username = data['name']
    email = data['email']

    user = session.query(User).filter_by(email=email).first()
    if not user:
        user = User(username=username, email=email)
        session.add(user)
        session.commit()
        print('added')

    output = ''
    output += '<h2>Welcome, '
    output += login_session['username']
    output += '!</h2>'
    print("done!")
    return output


# for revoking the credentitals - disconneting the user
@app.route('/gdisconnect')
def logout():
    access_token = login_session.get('access_token')
    print(access_token)
    if access_token is None:
        response = make_response(json.dumps('No user connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print(login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
          % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # result = json.loads(content.decode('utf-8'))
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        decors = session.query(Decor).all()
        recent = session.query(Item).limit(10)
        print('Sucessfully revoked')
        return render_template('firstpage.html',
                               decors=decors, recent=recent)
    else:
        response = make_response(json.dumps
                                 ('Failed to revoke token for given user.',
                                  400))
        response.headers['Content-Type'] = 'application/json'
        return response


# for login(existing account)
@app.route('/login', methods=['GET', 'POST'])
def login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = session.query(User).filter_by(username=username).first()
        if not username or not password:
            error = 'Missing username or password'
            return render_template('login.html', error=error)
        if user is None:
            error = 'Username not exist'
            return render_template('login.html', error=error)
        if user.username or user.verify_password(password):
            abc = True
            decors = session.query(Decor).all()
            recent = session.query(Item).all()
            # flash('Successfully logged in')
            return render_template('firstpage.html',
                                   abc=abc, decors=decors, recent=recent)
    else:
        return render_template('login.html', STATE=state)


# new user registration
@app.route('/userregistration', methods=['GET', 'POST'])
def newUser():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        if name is None or email is None or password is None:
            error = 'Missing arguments'
            return render_template('registration.html', error=error)
        if session.query(User).filter_by(email=email).first() is not None:
            flash('existing user')
            aemail = session.query(User).filter_by(email=email).first()
            g.aemail = aemail
            return redirect(url_for('showDecor'))
        user = User(username=name, email=email)
        user.hash_password(password)
        g.user = user
        session.add(user)
        session.commit()
        return redirect(url_for('showDecor'))
    else:
        return render_template('registration.html')


# Show all the Items and recently added
@app.route('/')
def showDecor():
    decors = session.query(Decor).all()
    recent = session.query(Item).limit(10)
    if 'username' in login_session is not None:
        abc = True
        decors = session.query(Decor).all()
        recent = session.query(Item).all()
        # flash('Successfully logged in')
        return render_template('firstpage.html',
                               abc=abc, decors=decors, recent=recent)
    else:
        return render_template('firstpage.html', decors=decors, recent=recent)


# Show all the items
@app.route('/catalog/<cat_name>/items', methods=['GET'])
def getItems(cat_name):
    alldecor = session.query(Decor).all()
    dec = session.query(Decor).filter_by(name=cat_name).one()
    item = session.query(Item).filter_by(d_id=dec.id).all()
    if 'username' in login_session is not None:
        abc = True
        alldecor = session.query(Decor).all()
        dec = session.query(Decor).filter_by(name=cat_name).one()
        item = session.query(Item).filter_by(d_id=dec.id).all()
        return render_template('listitems.html',
                               abc=abc, item=item, dec=dec, alldecor=alldecor)
    else:
        return render_template('listitems.html',
                               item=item, dec=dec, alldecor=alldecor)


# item description
@app.route('/catalog/<cat_name>/<item_name>', methods=["GET"])
def itemDescription(cat_name, item_name):
    decor = session.query(Decor).filter_by(name=cat_name).one()
    item = session.query(Item).filter_by(title=item_name).one()
    if 'username' in login_session is not None:
        abc = True
        decor = session.query(Decor).filter_by(name=cat_name).one()
        item = session.query(Item).filter_by(title=item_name).one()
        return render_template('itemdescription.html',
                               abc=abc, decor=decor, item=item)
    else:
        return render_template('itemdescription.html', decor=decor, item=item)


# edit item
@app.route('/catalog/<item_name>/edit/', methods=['GET', 'POST'])
def editItem(item_name):
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(title=item_name).one()
    decor = session.query(Decor).filter_by(id=item.d_id).one()
    name = login_session['username']
    user = session.query(User).filter_by(username=name).first()
    if item.u_id != user.id:
        flash("you can not edit this item")
        return redirect(url_for('showDecor'))
    if request.method == 'POST':
        if request.form['title']:
            item.title = request.form['title']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['decor']:
            selected = request.form['decor']
            decor = session.query(Decor).filter_by(name=selected).one()
            item.d_id = decor.id
        session.add(item)
        session.commit()
        return redirect(url_for('showDecor'))
    else:
        return render_template('edititem.html', item=item, decor=decor)


# delete item
@app.route('/catalog/<item_name>/delete', methods=['GET', 'POST'])
def deleteItem(item_name):
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Item).filter_by(title=item_name).one()
    name = login_session['username']
    user = session.query(User).filter_by(username=name).first()
    if item.u_id != user.id:
        flash(" You can not delete this item")
        return redirect(url_for('showDecor'))
    if request.method == "POST":
        session.delete(item)
        session.commit()
        return redirect(url_for('showDecor'))
    else:
        return render_template('deleteItem.html', item=item)


# add item
@app.route('/catalog/<decor_name>/add/', methods=['GET', 'POST'])
def addItem(decor_name):
    if 'username' not in login_session:
        return redirect('/login')
    decor = session.query(Decor).filter_by(name=decor_name).one()
    if request.method == 'POST':
        name = login_session['username']
        user = session.query(User).filter_by(username=name).first()
        newItem = Item(title=request.form['new-title-name'],
                       description=request.form['new-item-description'],
                       d_id=decor.id, u_id=user.id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('showDecor'))
    else:
        return render_template('newItem.html', decor=decor)


# add a new category

@app.route('/catalog/addCategory', methods=['GET', 'POST'])
def addCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Decor(name=request.form['new-name'])
        session.add(newCategory)
        session.commit()
        return redirect(url_for('showDecor'))
    else:
        return render_template('newCategory.html')


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
