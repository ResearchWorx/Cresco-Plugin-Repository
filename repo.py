# -*- coding: utf-8 -*-
"""
    Cresco-Plugin-Repository
    ~~~~~~~~~~~~~~~~~~~~~~~~

    A repository for the hosting of Cresco Plugins to be
    distributed to Cresco Agents

    :copyright: (c) 2016 Caylin Hickey.
    :license: Apache License 2.0, see LICENSE for more details
"""


import errno
import json
import os
import uuid
import shutil
from datetime import datetime
from flask import Flask, request, session, g, redirect, url_for, \
    render_template, flash, escape, send_file, abort, jsonify
from flask.ext.cors import CORS
from helpers import read_manifest
from sqlite3 import OperationalError
from sqlite3 import dbapi2 as sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from models import Admin


app = Flask(__name__)
CORS(app)
if not os.path.isfile('config.json'):
    print("No 'config.json' configuration file detected!")
    exit(1)
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
    if os.path.isdir(config['upload_dir']):
        shutil.rmtree(config['upload_dir'])
    os.mkdir(config['upload_dir'])
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
    try:
        plugin_names = query_db('SELECT DISTINCT name FROM plugins ORDER BY name ASC')
    except OperationalError:
        init_db()
        return redirect('/')
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


@app.route('/upload', methods=['GET'])
def upload_redirect():
    return redirect('/#upload')


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
        if manifest is None or len(manifest.main_section) < 1:
            flash('Invalid Cresco Plugin MANIFEST', 'upload_error')
            return redirect('/#upload')
        for key, value in manifest.main_section.iteritems():
            if key == 'artifactId':
                plugin_name = value
            if key == 'Implementation-Version':
                versions = value.split('.', 3)
                plugin_major_version = versions[0]
                plugin_minor_version = versions[1]
                plugin_maintenance_version = versions[2]
                plugin_build_version = versions[3]
        if plugin_name is None:
            flash('Invalid/Missing Cresco Plugin MANIFEST entry [artifactId]', 'upload_error')
            return redirect('/#upload')
        if plugin_major_version is None or plugin_minor_version is None or \
           plugin_maintenance_version is None or plugin_build_version is None:
            flash('Invalid/Missing Cresco Plugin MANIFEST entry [Implementation-Version]', 'upload_error')
            return redirect('/#upload')
        exists = query_db('SELECT id FROM plugins WHERE name = ? AND major_version = ? and minor_version = ? AND ' +
                          'maintenance_version = ?',
                          [plugin_name, plugin_major_version, plugin_minor_version, plugin_maintenance_version])
        if exists is not None and len(exists) > 0:
            flash('This version of ' + plugin_name + ' has already been uploaded', 'upload_error')
            return redirect('/#upload')
        jar_name = plugin_name + '-' + plugin_major_version + '.' + plugin_minor_version + '.' + \
            plugin_maintenance_version + '.jar'
        new_path = os.path.join(config['upload_dir'], plugin_name + '/' + plugin_major_version + '/' +
                                plugin_minor_version + '/' + plugin_maintenance_version + '/' + plugin_build_version)
        try:
            os.makedirs(new_path)
        except OSError as e:
            if e.errno == errno.EEXIST and os.path.isdir(new_path):
                pass
            else:
                flash('Failed to create plugin repository: ' + e.message, 'upload_error')
                return redirect('/#upload')
        new_path = os.path.join(config['upload_dir'], plugin_name + '/' + plugin_major_version + '/' +
                                plugin_minor_version + '/' + plugin_maintenance_version + '/' + plugin_build_version +
                                '/' + jar_name)
        shutil.move(full_filename, new_path)
        if os.path.isfile(full_filename):
            os.remove(full_filename)
        db = get_db()
        db.execute(
            'INSERT INTO plugins (id, name, path, major_version, minor_version, maintenance_version, build_version)' +
            ' VALUES (?, ?, ?, ?, ?, ?, ?)',
            [plugin_id, plugin_name, new_path, plugin_major_version,
             plugin_minor_version, plugin_maintenance_version, plugin_build_version])
        db.commit()
        flash('Uploaded ' + upload_file.filename, 'upload_success')
        return redirect('/')


@app.route('/plugins')
def plugins():
    epoch = datetime.utcfromtimestamp(0)
    ret = {}
    names = []
    plugin_names = query_db('SELECT DISTINCT(name) FROM plugins')
    for p_name, in list(plugin_names):
        names.append(p_name)
        plugin_results = query_db('SELECT id, uploaded, path, major_version, minor_version, maintenance_version, ' +
                                  'build_version FROM plugins WHERE name = ?', [p_name])
        versions = []
        entries = {}
        for p_id, uploaded, path, major, minor, maintenance, build, in list(plugin_results):
            versions.append('%s.%s.%s' % (major, minor, maintenance))
            entries['%s.%s.%s' % (major, minor, maintenance)] = \
                {'id': p_id, 'uploaded': long((datetime.strptime(uploaded, '%Y-%m-%d %H:%M:%S') -
                                               epoch).total_seconds() * 1000), 'path': path, 'major_version': major,
                 'minor_version': minor, 'maintenance_version': maintenance, 'build_version': build}
        entries['_versions'] = versions
        ret[p_name] = entries
        ret['_names'] = names
    return jsonify(ret)


@app.route('/plugins/<name>')
def plugins_for_name(name):
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


@app.route('/plugin/download/<name>-<major>.<minor>.<maint>.jar')
def download_latest_plugin(name, major, minor, maint):
    print('name: %s, major: %s, minor: %s, maint: %s', name, major, minor, maint)
    plugin = query_db('SELECT path FROM plugins WHERE name = ? AND major_version = ? AND minor_version = ? AND ' +
                      'maintenance_version = ? ORDER BY build_version DESC, uploaded DESC LIMIT 1',
                      [name, major, minor, maint])
    if len(plugin) == 0:
        return abort(404)
    return send_file(plugin[0][0])


@app.route('/plugin/download/<build>/<name>-<major>.<minor>.<maint>.jar')
def download_latest_plugin_at_build_version(name, major, minor, maint, build):
    print('name: %s, major: %s, minor: %s, maint: %s, build: %s', name, major, minor, maint, build)
    plugin = query_db('SELECT path FROM plugins WHERE name = ? AND major_version = ? AND minor_version = ? AND ' +
                      'maintenance_version = ? AND build_version = ? ORDER BY  uploaded DESC LIMIT 1',
                      [name, major, minor, maint, build])
    if len(plugin) == 0:
        return abort(404)
    return send_file(plugin[0][0])


@app.route('/plugin/download/<plugin_id>')
def download_plugin(plugin_id):
    plugin = query_db('SELECT * FROM plugins WHERE id = ?', [escape(plugin_id)], one=True)
    if plugin is None or len(plugin) == 0:
        flash('No such plugin found!', 'download-error')
        return redirect(url_for('index'))
    filename = '%s-%s.%s.%s.jar' % (plugin[2], plugin[4], plugin[5], plugin[6])
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
        os.rmdir(os.path.join(config['upload_dir'], '%s/%s/%s/%s/%s' % (plugin_name, plugin[4], plugin[5], plugin[6],
                                                                        plugin[7])))
        os.rmdir(os.path.join(config['upload_dir'], '%s/%s/%s/%s' % (plugin_name, plugin[4], plugin[5], plugin[6])))
        os.rmdir(os.path.join(config['upload_dir'], '%s/%s/%s' % (plugin_name, plugin[4], plugin[5])))
        os.rmdir(os.path.join(config['upload_dir'], '%s/%s' % (plugin_name, plugin[4])))
        os.rmdir(os.path.join(config['upload_dir'], plugin_name))
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
    app.run(debug=True, host='0.0.0.0', port=int(config['port']))
