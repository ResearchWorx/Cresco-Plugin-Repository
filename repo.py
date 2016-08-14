# -*- coding: utf-8 -*-
"""
    Cresco-Plugin-Repository
    ~~~~~~~~~~~~~~~~~~~~~~~~

    A repository for the hosting of Cresco Plugins to be
    distributed to Cresco Agents

    :copyright: (c) 2016 Caylin Hickey.
    :license: Apache License 2.0, see LICENSE for more details
"""


import json
import os
import uuid
import shutil
from flask import Flask, request, session, g, redirect, url_for, \
    render_template, flash, escape, send_file
from helpers import read_manifest
from sqlite3 import dbapi2 as sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from models import Admin


app = Flask(__name__)

with open('config.json') as json_data_file:
    config = json.load(json_data_file)
app.secret_key = config['secret_key']


def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(os.path.join(config['database']))
    rv.row_factory = sqlite3.Row
    return rv


def init_db():
    """Initializes the database."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    user_id = uuid.uuid4()
    db.execute('INSERT INTO admins (id, username, password, email, first_name, last_name) VALUES (?, ?, ?, ?, ?, ?)',
               [str(user_id), config['admin']['username'], generate_password_hash(config['admin']['password']),
                config['admin']['email'], config['admin']['first_name'], 'last_name'])
    db.commit()


@app.route('/initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    return redirect('/')


def get_db():
    """
        Opens a new database connection if there is none yet for
        the current application
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()
    if error is not None:
        print(error)


@app.route('/')
def index():
    admin = None
    if 'user_id' in session:
        ret = query_db('SELECT * FROM admins WHERE id = ?', [escape(session['user_id'])], one=True)
        admin = None
        if ret is not None and len(ret) > 0:
            admin = Admin(ret)
    plugin_names = query_db('SELECT DISTINCT name FROM plugins ORDER BY name ASC')
    return render_template('index.html', admin=admin, plugins=plugin_names)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        admin = query_db('SELECT id, password FROM admins WHERE username = ? OR email = ?',
                         [request.form['username'], request.form['username']], one=True)
        if admin is None or len(admin) == 0 or not check_password_hash(admin[1], request.form['password']):
            error = u'Invalid username or password'
        else:
            session['user_id'] = admin[0]
            return redirect(url_for('index'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1] in config['allowed_upload_extensions']


@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    ret = query_db('SELECT * FROM admins WHERE id = ?', [escape(session['user_id'])], one=True)
    if ret is None or len(ret) == 0:
        return redirect(url_for('index'))
    if 'pluginFile' not in request.files:
        flash('No plugin was specified for upload', 'upload_error')
        return redirect('/#upload')
    upload_file = request.files['pluginFile']
    if upload_file.filename == '':
        flash('No plugin was specified for upload', 'upload_error')
        return redirect('/#upload')
    if upload_file and allowed_file(upload_file.filename):
        filename = secure_filename(upload_file.filename)
        full_filename = os.path.join(config['upload_dir'], filename)
        upload_file.save(full_filename)
        plugin_id = str(uuid.uuid4())
        plugin_name = None
        plugin_major_version = None
        plugin_minor_version = None
        plugin_maintenance_version = None
        plugin_build_version = None
        manifest = read_manifest(full_filename)
        for key, value in manifest.main_section.iteritems():
            if key == 'artifactId':
                plugin_name = value
            if key == 'Implementation-Version':
                versions = value.split('.', 3)
                plugin_major_version = versions[0]
                plugin_minor_version = versions[1]
                plugin_maintenance_version = versions[2]
                plugin_build_version = versions[3]
        jar_name = plugin_name + '-' + plugin_major_version + '.' + plugin_minor_version + '.' + \
                    plugin_maintenance_version + '.jar'
        new_path = os.path.join(config['upload_dir'], plugin_name)
        if not os.path.exists(new_path):
            os.makedirs(new_path)
        new_path = os.path.join(config['upload_dir'], plugin_name + '/' + plugin_major_version)
        if not os.path.exists(new_path):
            os.makedirs(new_path)
        new_path = os.path.join(config['upload_dir'], plugin_name + '/' + plugin_major_version + '/' +
                                plugin_minor_version)
        if not os.path.exists(new_path):
            os.makedirs(new_path)
        new_path = os.path.join(config['upload_dir'], plugin_name + '/' + plugin_major_version + '/' +
                                plugin_minor_version + '/' + plugin_maintenance_version)
        if not os.path.exists(new_path):
            os.makedirs(new_path)
        new_path = os.path.join(config['upload_dir'], plugin_name + '/' + plugin_major_version + '/' +
                                plugin_minor_version + '/' + plugin_maintenance_version + '/' + plugin_build_version)
        if not os.path.exists(new_path):
            os.makedirs(new_path)
        new_path = os.path.join(config['upload_dir'], plugin_name + '/' + plugin_major_version + '/' +
                                plugin_minor_version + '/' + plugin_maintenance_version + '/' + plugin_build_version +
                                '/' + jar_name)
        shutil.move(full_filename, new_path)
        db = get_db()
        db.execute(
            'INSERT INTO plugins (id, name, path, major_version, minor_version, maintenance_version, build_version)' +
            ' VALUES (?, ?, ?, ?, ?, ?, ?)',
            [plugin_id, plugin_name, new_path, plugin_major_version,
             plugin_minor_version, plugin_maintenance_version, plugin_build_version])
        db.commit()
        flash('Uploaded ' + upload_file.filename, 'upload_success')
        return redirect('/')


@app.route('/plugins/<name>')
def plugins(name):
    admin = None
    if 'user_id' in session:
        ret = query_db('SELECT * FROM admins WHERE id = ?', [escape(session['user_id'])], one=True)
        admin = None
        if ret is not None and len(ret) > 0:
            admin = Admin(ret)
    view_plugins = query_db('SELECT * FROM plugins WHERE name = ? ORDER BY major_version DESC, minor_version DESC,' +
                            'maintenance_version DESC, uploaded DESC', [escape(name)])
    if view_plugins is None or len(view_plugins) == 0:
        return redirect(url_for('index'))
    return render_template('plugins.html', admin=admin, name=name, plugins=view_plugins)


@app.route('/plugin/download/<plugin_id>')
def download_plugin(plugin_id):
    plugin = query_db('SELECT * FROM plugins WHERE id = ?', [escape(plugin_id)], one=True)
    if plugin is None or len(plugin) == 0:
        flash('No such plugin found!', 'download-error')
        return redirect(url_for('index'))
    filename = plugin[2] + '-' + plugin[4] + '.' + plugin[5] + '.' + plugin[6] + '.jar'
    return send_file(plugin[3], as_attachment=True, attachment_filename=filename)


@app.route('/plugin/delete/<plugin_id>')
def delete_plugin(plugin_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    ret = query_db('SELECT * FROM admins WHERE id = ?', [escape(session['user_id'])], one=True)
    if ret is None or len(ret) == 0:
        return redirect(url_for('index'))
    plugin = query_db('SELECT * FROM plugins WHERE id = ?', [escape(plugin_id)], one=True)
    if plugin is None or len(plugin) == 0:
        flash('No such plugin found!', 'download-error')
        return redirect(url_for('index'))
    try:
        os.remove(plugin[3])
    except OSError:
        pass
    plugin_name = plugin[2]
    name_still_exists = True
    try:
        os.rmdir(os.path.join(config['upload_dir'], plugin[2] + '/' + plugin[4] + '/' + plugin[5] + '/' + plugin[6] +
                              '/' + plugin[7]))
        os.rmdir(os.path.join(config['upload_dir'], plugin[2] + '/' + plugin[4] + '/' + plugin[5] + '/' + plugin[6]))
        os.rmdir(os.path.join(config['upload_dir'], plugin[2] + '/' + plugin[4] + '/' + plugin[5]))
        os.rmdir(os.path.join(config['upload_dir'], plugin[2] + '/' + plugin[4]))
        os.rmdir(os.path.join(config['upload_dir'], plugin[2]))
        name_still_exists = False
    except OSError:
        pass
    db = get_db()
    db.execute("DELETE FROM plugins WHERE id = ?", [plugin_id])
    db.commit()
    if name_still_exists:
        return redirect(url_for('plugins', name=plugin_name))
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=config['port'])
