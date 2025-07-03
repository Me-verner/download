from flask import Flask, render_template_string, request, redirect, url_for, send_file, flash, session, abort, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from zipfile import ZipFile
import os
import shutil
import json
import time
from datetime import datetime
import mimetypes

app = Flask(__name__)
app.secret_key = "very_secret_key_change_in_production"

USERNAME = "sasan"
PASSWORD = "sasan"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    if user_id == USERNAME:
        user = User()
        user.id = USERNAME
        return user
    return None

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    if data.get("username") == USERNAME and data.get("password") == PASSWORD:
        user = User()
        user.id = USERNAME
        login_user(user)
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    logout_user()
    return jsonify({"success": True})

@app.route("/api/files", methods=["GET"])
@app.route("/api/files/", methods=["GET"])
@app.route("/api/files/<path:req_path>", methods=["GET"])
@login_required
def api_files(req_path=''):
    BASE_DIR = os.path.abspath(".")
    
    # Clean the path
    req_path = req_path.strip('/')
    
    if not req_path:
        abs_path = BASE_DIR
    else:
        abs_path = os.path.join(BASE_DIR, req_path)
    
    # Normalize the path
    abs_path = os.path.abspath(abs_path)
    
    # Security check - ensure we're not going outside BASE_DIR
    if not abs_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    if not os.path.exists(abs_path):
        return jsonify({"error": "Path not found"}), 404
    
    if not os.path.isdir(abs_path):
        return jsonify({"error": "Not a directory"}), 400
    
    files = []
    folders = []
    
    try:
        for entry in os.listdir(abs_path):
            if entry.startswith('.'):
                continue
                
            entry_path = os.path.join(abs_path, entry)
            try:
                stat = os.stat(entry_path)
                
                item = {
                    "name": entry,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "is_dir": os.path.isdir(entry_path)
                }
                
                if item["is_dir"]:
                    folders.append(item)
                else:
                    files.append(item)
            except OSError:
                # Skip files we can't stat
                continue
        
        folders.sort(key=lambda x: x["name"].lower())
        files.sort(key=lambda x: x["name"].lower())
        
        # Calculate parent path
        parent_path = None
        if req_path:
            parent_parts = req_path.split('/')
            if len(parent_parts) > 1:
                parent_path = '/'.join(parent_parts[:-1])
            else:
                parent_path = ''
        
        return jsonify({
            "current_path": req_path,
            "parent_path": parent_path,
            "folders": folders,
            "files": files
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/file/content", methods=["GET"])
@app.route("/api/file/content/<path:req_path>", methods=["GET"])
@login_required
def api_get_file_content(req_path=''):
    filename = request.args.get('filename')
    if not filename:
        return jsonify({"error": "Filename required"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        file_path = os.path.join(BASE_DIR, req_path, filename)
    else:
        file_path = os.path.join(BASE_DIR, filename)
    
    file_path = os.path.abspath(file_path)
    if not file_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"content": content, "filename": filename})
    except UnicodeDecodeError:
        return jsonify({"error": "Binary file cannot be edited"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/file/save", methods=["POST"])
@app.route("/api/file/save/<path:req_path>", methods=["POST"])
@login_required
def api_save_file(req_path=''):
    data = request.get_json()
    filename = data.get("filename")
    content = data.get("content", "")
    
    if not filename:
        return jsonify({"error": "Filename required"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        file_path = os.path.join(BASE_DIR, req_path, filename)
    else:
        file_path = os.path.join(BASE_DIR, filename)
    
    file_path = os.path.abspath(file_path)
    if not file_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"success": True, "message": "File saved successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/file/create", methods=["POST"])
@app.route("/api/file/create/<path:req_path>", methods=["POST"])
@login_required
def api_create_file(req_path=''):
    data = request.get_json()
    filename = data.get("filename")
    
    if not filename:
        return jsonify({"error": "Filename required"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        file_path = os.path.join(BASE_DIR, req_path, filename)
    else:
        file_path = os.path.join(BASE_DIR, filename)
    
    file_path = os.path.abspath(file_path)
    if not file_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    if os.path.exists(file_path):
        return jsonify({"error": "File already exists"}), 400
    
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("")
        return jsonify({"success": True, "message": "File created successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/file/delete", methods=["DELETE"])
@app.route("/api/file/delete/<path:req_path>", methods=["DELETE"])
@login_required
def api_delete_file(req_path=''):
    filename = request.args.get('filename')
    if not filename:
        return jsonify({"error": "Filename required"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        file_path = os.path.join(BASE_DIR, req_path, filename)
    else:
        file_path = os.path.join(BASE_DIR, filename)
    
    file_path = os.path.abspath(file_path)
    if not file_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    try:
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
        else:
            os.remove(file_path)
        return jsonify({"success": True, "message": "File deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/file/rename", methods=["POST"])
@app.route("/api/file/rename/<path:req_path>", methods=["POST"])
@login_required
def api_rename_file(req_path=''):
    data = request.get_json()
    old_name = data.get("old_name")
    new_name = data.get("new_name")
    
    if not old_name or not new_name:
        return jsonify({"error": "Both old_name and new_name required"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        old_path = os.path.join(BASE_DIR, req_path, old_name)
        new_path = os.path.join(BASE_DIR, req_path, new_name)
    else:
        old_path = os.path.join(BASE_DIR, old_name)
        new_path = os.path.join(BASE_DIR, new_name)
    
    old_path = os.path.abspath(old_path)
    new_path = os.path.abspath(new_path)
    if not old_path.startswith(BASE_DIR) or not new_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    if not os.path.exists(old_path):
        return jsonify({"error": "File not found"}), 404
    
    if os.path.exists(new_path):
        return jsonify({"error": "Target name already exists"}), 400
    
    try:
        os.rename(old_path, new_path)
        return jsonify({"success": True, "message": "File renamed successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/upload", methods=["POST"])
@app.route("/api/upload/<path:req_path>", methods=["POST"])
@login_required
def api_upload(req_path=''):
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        upload_path = os.path.join(BASE_DIR, req_path)
    else:
        upload_path = BASE_DIR
    
    upload_path = os.path.abspath(upload_path)
    if not upload_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    try:
        filename = secure_filename(file.filename)
        file.save(os.path.join(upload_path, filename))
        return jsonify({"success": True, "message": "File uploaded successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/download")
@app.route("/api/download/<path:req_path>")
@login_required
def api_download(req_path=''):
    filename = request.args.get('filename')
    if not filename:
        return jsonify({"error": "Filename required"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        file_path = os.path.join(BASE_DIR, req_path, filename)
    else:
        file_path = os.path.join(BASE_DIR, filename)
    
    file_path = os.path.abspath(file_path)
    if not file_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    # Get the mimetype
    mimetype = mimetypes.guess_type(file_path)[0]
    if not mimetype:
        mimetype = 'application/octet-stream'
    
    return send_file(file_path, as_attachment=True, download_name=filename, mimetype=mimetype)

@app.route("/api/zip", methods=["POST"])
@app.route("/api/zip/<path:req_path>", methods=["POST"])
@login_required
def api_create_zip(req_path=''):
    data = request.get_json()
    files_to_zip = data.get("files", [])
    zip_name = data.get("zip_name", "archive.zip")
    
    if not files_to_zip:
        return jsonify({"error": "No files selected"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        base_path = os.path.join(BASE_DIR, req_path)
    else:
        base_path = BASE_DIR
    
    base_path = os.path.abspath(base_path)
    if not base_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    zip_path = os.path.join(base_path, zip_name)
    
    try:
        with ZipFile(zip_path, "w") as zipf:
            for filename in files_to_zip:
                file_path = os.path.join(base_path, filename)
                if os.path.exists(file_path):
                    if os.path.isdir(file_path):
                        for root, dirs, files in os.walk(file_path):
                            for file in files:
                                file_full_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_full_path, base_path)
                                zipf.write(file_full_path, arcname)
                    else:
                        zipf.write(file_path, filename)
        
        return jsonify({"success": True, "message": f"Created {zip_name} successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/unzip", methods=["POST"])
@app.route("/api/unzip/<path:req_path>", methods=["POST"])
@login_required
def api_unzip(req_path=''):
    data = request.get_json()
    zip_filename = data.get("filename")
    
    if not zip_filename:
        return jsonify({"error": "Filename required"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        zip_path = os.path.join(BASE_DIR, req_path, zip_filename)
        extract_path = os.path.join(BASE_DIR, req_path)
    else:
        zip_path = os.path.join(BASE_DIR, zip_filename)
        extract_path = BASE_DIR
    
    zip_path = os.path.abspath(zip_path)
    extract_path = os.path.abspath(extract_path)
    if not zip_path.startswith(BASE_DIR) or not extract_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    if not os.path.exists(zip_path):
        return jsonify({"error": "ZIP file not found"}), 404
    
    try:
        with ZipFile(zip_path, "r") as zipf:
            zipf.extractall(extract_path)
        return jsonify({"success": True, "message": f"Extracted {zip_filename} successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/create_folder", methods=["POST"])
@app.route("/api/create_folder/<path:req_path>", methods=["POST"])
@login_required
def api_create_folder(req_path=''):
    data = request.get_json()
    folder_name = data.get("folder_name")
    
    if not folder_name:
        return jsonify({"error": "Folder name required"}), 400
    
    BASE_DIR = os.path.abspath(".")
    if req_path:
        folder_path = os.path.join(BASE_DIR, req_path, folder_name)
    else:
        folder_path = os.path.join(BASE_DIR, folder_name)
    
    folder_path = os.path.abspath(folder_path)
    if not folder_path.startswith(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403
    
    if os.path.exists(folder_path):
        return jsonify({"error": "Folder already exists"}), 400
    
    try:
        os.makedirs(folder_path)
        return jsonify({"success": True, "message": "Folder created successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Complete SFTP File Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/theme/monokai.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/python/python.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/javascript/javascript.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/css/css.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/xml/xml.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/shell/shell.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/sql/sql.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/addon/edit/closebrackets.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/addon/edit/matchbrackets.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/addon/selection/active-line.min.js"></script>
    <style>
        body { background: #0f172a; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .hidden { display: none !important; }
        .file-icon { width: 20px; text-align: center; }
        .CodeMirror {
            height: 100%;
            font-size: 14px;
            line-height: 1.5;
        }
        .pulse {
            animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: .5; }
        }
        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #1e293b;
        }
        ::-webkit-scrollbar-thumb {
            background: #475569;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #64748b;
        }
    </style>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen">
    <!-- Login Screen - Shown by default -->
    <div id="login-screen" class="min-h-screen flex items-center justify-center">
        <div class="bg-slate-800 p-8 rounded-xl shadow-2xl w-full max-w-md border border-slate-700">
            <div class="text-center mb-8">
                <div class="bg-blue-600 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fas fa-server text-2xl text-white"></i>
                </div>
                <h1 class="text-3xl font-bold text-slate-100 mb-2">SFTP Manager</h1>
                <p class="text-slate-400">Secure File Transfer Protocol</p>
            </div>
            <form id="login-form" class="space-y-6">
                <div>
                    <label class="block text-sm font-medium text-slate-300 mb-2">Username</label>
                    <input 
                        id="username"
                        type="text" 
                        placeholder="Enter your username" 
                        value="sasan"
                        class="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white placeholder-slate-400"
                        required
                        autocomplete="username"
                    />
                </div>
                <div>
                    <label class="block text-sm font-medium text-slate-300 mb-2">Password</label>
                    <input 
                        id="password"
                        type="password" 
                        placeholder="Enter your password" 
                        value="sasan"
                        class="w-full px-4 py-3 bg-slate-700 border border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-white placeholder-slate-400"
                        required
                        autocomplete="current-password"
                    />
                </div>
                <button 
                    type="submit" 
                    id="login-btn"
                    class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg transition-colors flex items-center justify-center"
                >
                    <i class="fas fa-sign-in-alt mr-2"></i>
                    Connect
                </button>
            </form>
            <div id="login-error" class="hidden mt-4 p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-200">
                <div class="flex items-center">
                    <i class="fas fa-exclamation-triangle mr-2 text-red-400"></i>
                    <span id="error-message"></span>
                </div>
            </div>
        </div>
    </div>

    <!-- Main File Manager -->
    <div id="file-manager" class="hidden min-h-screen flex flex-col">
        <!-- Header -->
        <header class="bg-slate-800 border-b border-slate-700 px-6 py-4 flex-shrink-0">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                    <div class="bg-blue-600 w-10 h-10 rounded-lg flex items-center justify-center">
                        <i class="fas fa-server text-white"></i>
                    </div>
                    <div>
                        <h1 class="text-xl font-bold">SFTP File Manager</h1>
                        <p class="text-sm text-slate-400">Secure File Transfer Protocol</p>
                    </div>
                </div>
                <div class="flex items-center space-x-3">
                    <span id="current-time" class="text-sm text-slate-400"></span>
                    <button id="refresh-btn" class="px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors" title="Refresh Directory">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                    <button id="logout-btn" class="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg transition-colors">
                        <i class="fas fa-sign-out-alt mr-2"></i>
                        Disconnect
                    </button>
                </div>
            </div>
        </header>

        <!-- Navigation -->
        <nav class="bg-slate-800 border-b border-slate-700 px-6 py-3 flex-shrink-0">
            <div class="flex items-center space-x-4">
                <div id="breadcrumb" class="flex items-center space-x-2 flex-1">
                    <i class="fas fa-home text-blue-500"></i>
                    <span class="text-blue-400 cursor-pointer hover:text-blue-300 px-2 py-1 rounded" onclick="loadFiles('')">Home</span>
                </div>
                <div class="flex items-center space-x-2">
                    <input 
                        id="custom-path"
                        type="text" 
                        placeholder="Enter path (e.g., folder/subfolder)..." 
                        class="px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white w-80 focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder-slate-400"
                    />
                    <button id="navigate-btn" class="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors" title="Navigate">
                        <i class="fas fa-arrow-right"></i>
                    </button>
                </div>
            </div>
        </nav>

        <!-- Toolbar -->
        <div class="bg-slate-800 border-b border-slate-700 px-6 py-3 flex-shrink-0">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <button id="new-file-btn" class="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg transition-colors flex items-center">
                        <i class="fas fa-file-plus mr-2"></i>
                        New File
                    </button>
                    <button id="new-folder-btn" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors flex items-center">
                        <i class="fas fa-folder-plus mr-2"></i>
                        New Folder
                    </button>
                    <label class="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg transition-colors cursor-pointer flex items-center">
                        <i class="fas fa-upload mr-2"></i>
                        Upload
                        <input type="file" id="file-upload" multiple class="hidden" />
                    </label>
                </div>
                <div class="flex items-center space-x-3">
                    <span id="selection-count" class="text-sm text-slate-400"></span>
                    <button id="zip-btn" class="px-4 py-2 bg-orange-600 hover:bg-orange-700 rounded-lg transition-colors flex items-center opacity-50" disabled>
                        <i class="fas fa-file-archive mr-2"></i>
                        Create ZIP
                    </button>
                    <button id="download-btn" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 rounded-lg transition-colors flex items-center opacity-50" disabled>
                        <i class="fas fa-download mr-2"></i>
                        Download
                    </button>
                    <button id="delete-btn" class="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg transition-colors flex items-center opacity-50" disabled>
                        <i class="fas fa-trash mr-2"></i>
                        Delete
                    </button>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="flex-1 flex min-h-0">
            <!-- File List Panel -->
            <div id="file-panel" class="flex-1 flex flex-col">
                <div class="flex-1 p-6 overflow-auto">
                    <div id="loading-files" class="hidden text-center py-8">
                        <i class="fas fa-spinner fa-spin text-2xl text-blue-500"></i>
                        <p class="mt-2 text-slate-400">Loading directory...</p>
                    </div>
                    
                    <div id="file-table-container" class="bg-slate-800 rounded-xl overflow-hidden border border-slate-700">
                        <table class="w-full">
                            <thead class="bg-slate-700">
                                <tr>
                                    <th class="px-4 py-3 text-left w-12">
                                        <input type="checkbox" id="select-all" class="rounded" />
                                    </th>
                                    <th class="px-4 py-3 text-left">Name</th>
                                    <th class="px-4 py-3 text-left w-24">Size</th>
                                    <th class="px-4 py-3 text-left w-40">Modified</th>
                                    <th class="px-4 py-3 text-left w-32">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="file-list">
                                <!-- Files will be loaded here -->
                            </tbody>
                        </table>
                    </div>
                    
                    <div id="empty-state" class="hidden text-center py-16">
                        <i class="fas fa-folder-open text-6xl text-slate-500 mb-4"></i>
                        <h3 class="text-xl text-slate-400 mb-2">Directory is empty</h3>
                        <p class="text-slate-500">Upload files or create new ones to get started</p>
                    </div>
                </div>
            </div>

            <!-- File Editor Panel -->
            <div id="editor-panel" class="hidden w-2/3 border-l border-slate-700 flex flex-col">
                <!-- Editor Header -->
                <div class="bg-slate-800 border-b border-slate-700 px-6 py-4 flex items-center justify-between">
                    <div class="flex items-center space-x-4">
                        <i id="editor-icon" class="text-xl"></i>
                        <div>
                            <h3 id="editor-filename" class="text-lg font-medium"></h3>
                            <p id="editor-path" class="text-sm text-slate-400"></p>
                        </div>
                        <span id="editor-language" class="px-2 py-1 bg-slate-700 rounded text-xs uppercase"></span>
                    </div>
                    <div class="flex items-center space-x-2">
                        <button id="save-btn" class="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg transition-colors flex items-center">
                            <i class="fas fa-save mr-2"></i>
                            Save
                        </button>
                        <button id="close-editor-btn" class="px-4 py-2 bg-slate-600 hover:bg-slate-700 rounded-lg transition-colors">
                            <i class="fas fa-times mr-2"></i>
                            Close
                        </button>
                    </div>
                </div>
                
                <!-- Editor Content -->
                <div class="flex-1" id="editor-container" style="height: calc(100vh - 200px);">
                    <!-- CodeMirror will be initialized here -->
                </div>

                <!-- Editor Status Bar -->
                <div class="bg-slate-800 border-t border-slate-700 px-6 py-2 flex items-center justify-between text-sm">
                    <div class="flex items-center space-x-4">
                        <span id="editor-lines">Lines: 1</span>
                        <span id="editor-chars">Characters: 0</span>
                        <span id="editor-size">Size: 0 B</span>
                    </div>
                    <div id="editor-cursor">Line 1, Column 1</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Simple Modals -->
    <div id="modal-overlay" class="hidden fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div id="modal-content" class="bg-slate-800 p-6 rounded-xl border border-slate-700 min-w-96">
            <h3 id="modal-title" class="text-lg font-bold mb-4"></h3>
            <input id="modal-input" type="text" class="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500" />
            <div class="flex justify-end space-x-2">
                <button id="modal-cancel" class="px-4 py-2 bg-slate-600 hover:bg-slate-700 rounded-lg transition-colors">Cancel</button>
                <button id="modal-confirm" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">Confirm</button>
            </div>
        </div>
    </div>

    <!-- Message Toast -->
    <div id="message-toast" class="hidden fixed bottom-4 right-4 z-50">
        <div id="message-content" class="p-4 rounded-lg shadow-lg border max-w-sm">
            <div class="flex items-center">
                <i id="message-icon" class="mr-3 text-lg"></i>
                <span id="message-text" class="font-medium"></span>
            </div>
        </div>
    </div>

    <script>
        // Global variables
        let currentPath = '';
        let selectedFiles = [];
        let isLoggedIn = false;
        let currentEditFile = null;
        let autoRefreshInterval = null;
        let modalCallback = null;
        let codeEditor = null;

        // Initialize on page load
        window.addEventListener('load', function() {
            console.log('Page loaded, initializing...');
            
            // Focus username input
            document.getElementById('username').focus();
            
            // Setup event listeners
            setupEventListeners();
            
            // Update time
            updateTime();
            setInterval(updateTime, 1000);
        });

        function updateTime() {
            const now = new Date();
            document.getElementById('current-time').textContent = now.toLocaleString();
        }

        function setupEventListeners() {
            // Login form
            document.getElementById('login-form').addEventListener('submit', function(e) {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                login(username, password);
            });

            // Logout
            document.getElementById('logout-btn').addEventListener('click', logout);

            // Navigation
            document.getElementById('refresh-btn').addEventListener('click', function() {
                loadFiles(currentPath);
            });

            document.getElementById('navigate-btn').addEventListener('click', navigateToPath);
            document.getElementById('custom-path').addEventListener('keyup', function(e) {
                if (e.key === 'Enter') {
                    navigateToPath();
                }
            });

            // File operations
            document.getElementById('new-file-btn').addEventListener('click', function() {
                showModal('Create New File', '', createFile);
            });

            document.getElementById('new-folder-btn').addEventListener('click', function() {
                showModal('Create New Folder', '', createFolder);
            });

            document.getElementById('zip-btn').addEventListener('click', function() {
                if (selectedFiles.length > 0) {
                    showModal('Create ZIP Archive', 'archive.zip', function(zipName) {
                        createZip(selectedFiles, zipName);
                    });
                }
            });

            document.getElementById('download-btn').addEventListener('click', function() {
                selectedFiles.forEach(filename => downloadFile(filename));
            });

            document.getElementById('delete-btn').addEventListener('click', function() {
                if (selectedFiles.length > 0 && confirm('Delete ' + selectedFiles.length + ' item(s)?')) {
                    selectedFiles.forEach(filename => deleteFile(filename));
                }
            });

            // File upload
            document.getElementById('file-upload').addEventListener('change', function(e) {
                uploadFiles(e.target.files);
                e.target.value = '';
            });

            // Editor
            document.getElementById('save-btn').addEventListener('click', saveFile);
            document.getElementById('close-editor-btn').addEventListener('click', closeEditor);

            // Selection
            document.getElementById('select-all').addEventListener('change', function(e) {
                const checkboxes = document.querySelectorAll('.file-checkbox');
                checkboxes.forEach(cb => {
                    cb.checked = e.target.checked;
                });
                updateSelectedFiles();
            });

            // Modal
            document.getElementById('modal-cancel').addEventListener('click', hideModal);
            document.getElementById('modal-confirm').addEventListener('click', function() {
                const value = document.getElementById('modal-input').value.trim();
                if (value && modalCallback) {
                    modalCallback(value);
                    hideModal();
                }
            });

            document.getElementById('modal-input').addEventListener('keyup', function(e) {
                if (e.key === 'Enter') {
                    const value = this.value.trim();
                    if (value && modalCallback) {
                        modalCallback(value);
                        hideModal();
                    }
                }
            });

            // Dynamic events
            document.addEventListener('change', function(e) {
                if (e.target.classList.contains('file-checkbox')) {
                    updateSelectedFiles();
                }
            });

            document.addEventListener('click', function(e) {
                // File/folder navigation
                if (e.target.closest('.file-name')) {
                    const element = e.target.closest('.file-name');
                    const name = element.dataset.name;
                    const type = element.dataset.type;
                    const parentPath = element.dataset.parent;
                    
                    if (name === '..') {
                        loadFiles(parentPath);
                    } else if (type === 'folder') {
                        const newPath = currentPath ? currentPath + '/' + name : name;
                        loadFiles(newPath);
                    } else {
                        openFileEditor(name);
                    }
                }

                // Action buttons
                if (e.target.closest('.edit-btn')) {
                    const name = e.target.closest('.edit-btn').dataset.name;
                    openFileEditor(name);
                }
                
                if (e.target.closest('.delete-btn')) {
                    const name = e.target.closest('.delete-btn').dataset.name;
                    if (confirm('Delete "' + name + '"?')) {
                        deleteFile(name);
                    }
                }
                
                if (e.target.closest('.download-btn')) {
                    const name = e.target.closest('.download-btn').dataset.name;
                    downloadFile(name);
                }
            });

            // Keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                if (e.ctrlKey || e.metaKey) {
                    switch (e.key) {
                        case 's':
                            if (!document.getElementById('editor-panel').classList.contains('hidden')) {
                                e.preventDefault();
                                saveFile();
                            }
                            break;
                        case 'r':
                            e.preventDefault();
                            loadFiles(currentPath);
                            break;
                    }
                }
            });
        }

        function navigateToPath() {
            let path = document.getElementById('custom-path').value.trim();
            // Clean the path
            path = path.replace(/^[\\/]+/, '').replace(/[\\/]+$/, '').replace(/\\\\/g, '/');
            loadFiles(path);
        }

        function updateSelectedFiles() {
            selectedFiles = [];
            const checkboxes = document.querySelectorAll('.file-checkbox:checked');
            checkboxes.forEach(cb => {
                selectedFiles.push(cb.value);
            });
            updateSelectionUI();
        }

        // Core functions
        async function login(username, password) {
            const loginBtn = document.getElementById('login-btn');
            loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Connecting...';
            loginBtn.disabled = true;

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    isLoggedIn = true;
                    document.getElementById('login-screen').classList.add('hidden');
                    document.getElementById('file-manager').classList.remove('hidden');
                    await loadFiles('');
                    startAutoRefresh();
                    showMessage('Connected successfully!', 'success');
                } else {
                    document.getElementById('login-error').classList.remove('hidden');
                    document.getElementById('error-message').textContent = data.message || 'Invalid credentials';
                }
            } catch (error) {
                document.getElementById('login-error').classList.remove('hidden');
                document.getElementById('error-message').textContent = 'Connection failed';
            }

            loginBtn.innerHTML = '<i class="fas fa-sign-in-alt mr-2"></i>Connect';
            loginBtn.disabled = false;
        }

        async function logout() {
            try {
                await fetch('/api/logout', { method: 'POST' });
            } catch (error) {
                console.error('Logout error:', error);
            }
            
            isLoggedIn = false;
            stopAutoRefresh();
            closeEditor();
            
            document.getElementById('file-manager').classList.add('hidden');
            document.getElementById('login-screen').classList.remove('hidden');
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
            document.getElementById('login-error').classList.add('hidden');
        }

        async function loadFiles(path, showLoading = true) {
            if (showLoading) {
                document.getElementById('loading-files').classList.remove('hidden');
                document.getElementById('file-table-container').classList.add('hidden');
                document.getElementById('empty-state').classList.add('hidden');
            }

            // Store current selections before reload
            const previousSelections = [...selectedFiles];

            try {
                const url = path ? '/api/files/' + encodeURIComponent(path) : '/api/files';
                const response = await fetch(url);
                const data = await response.json();
                
                if (response.ok) {
                    currentPath = data.current_path || path;
                    document.getElementById('custom-path').value = currentPath;
                    
                    renderFiles(data);
                    updateBreadcrumb(currentPath);
                    
                    // Restore selections after reload
                    if (!showLoading && previousSelections.length > 0) {
                        previousSelections.forEach(filename => {
                            const checkbox = document.querySelector('.file-checkbox[value="' + CSS.escape(filename) + '"]');
                            if (checkbox) {
                                checkbox.checked = true;
                            }
                        });
                        updateSelectedFiles();
                    } else {
                        selectedFiles = [];
                        updateSelectionUI();
                    }
                } else {
                    showMessage(data.error || 'Failed to load directory', 'error');
                    // If path not found, go back to home
                    if (response.status === 404 && path !== '') {
                        loadFiles('');
                    }
                }
            } catch (error) {
                showMessage('Failed to load directory', 'error');
                if (path !== '') {
                    loadFiles('');
                }
            }
            
            if (showLoading) {
                document.getElementById('loading-files').classList.add('hidden');
            }
        }

        function renderFiles(data) {
            const fileList = document.getElementById('file-list');
            fileList.innerHTML = '';
            
            // Parent directory
            if (data.parent_path !== null) {
                const row = createFileRow('..', 'folder', '-', '-', true, data.parent_path);
                fileList.appendChild(row);
            }
            
            // Folders
            data.folders.forEach(folder => {
                const row = createFileRow(folder.name, 'folder', '-', formatDate(folder.modified), false);
                fileList.appendChild(row);
            });
            
            // Files
            data.files.forEach(file => {
                const row = createFileRow(file.name, 'file', formatSize(file.size), formatDate(file.modified), false);
                fileList.appendChild(row);
            });
            
            if (data.folders.length === 0 && data.files.length === 0 && data.parent_path === null) {
                document.getElementById('empty-state').classList.remove('hidden');
                document.getElementById('file-table-container').classList.add('hidden');
            } else {
                document.getElementById('file-table-container').classList.remove('hidden');
                document.getElementById('empty-state').classList.add('hidden');
            }

            // Update select all checkbox
            document.getElementById('select-all').checked = false;
        }

        function createFileRow(name, type, size, modified, isParent, parentPath) {
            parentPath = parentPath || '';
            const row = document.createElement('tr');
            row.className = 'border-t border-slate-700 hover:bg-slate-700 transition-colors';
            
            const isFolder = type === 'folder';
            const icon = isParent ? 'fas fa-level-up-alt text-blue-400' : 
                        isFolder ? 'fas fa-folder text-yellow-500' : getFileIcon(name);
            
            let rowHTML = '<td class="px-4 py-3">';
            if (!isParent) {
                rowHTML += '<input type="checkbox" class="file-checkbox rounded" value="' + escapeHtml(name) + '" />';
            }
            rowHTML += '</td>';
            
            rowHTML += '<td class="px-4 py-3">';
            rowHTML += '<div class="flex items-center space-x-3 cursor-pointer file-name" data-name="' + escapeHtml(name) + '" data-type="' + type + '" data-parent="' + escapeHtml(parentPath) + '">';
            rowHTML += '<i class="' + icon + ' file-icon"></i>';
            rowHTML += '<span class="' + (isParent ? 'text-blue-400' : '') + '">' + escapeHtml(name) + '</span>';
            rowHTML += '</div></td>';
            
            rowHTML += '<td class="px-4 py-3 text-slate-400">' + size + '</td>';
            rowHTML += '<td class="px-4 py-3 text-slate-400">' + modified + '</td>';
            rowHTML += '<td class="px-4 py-3">';
            
            if (!isParent) {
                rowHTML += '<div class="flex items-center space-x-2">';
                if (!isFolder) {
                    rowHTML += '<button class="text-blue-400 hover:text-blue-300 edit-btn" data-name="' + escapeHtml(name) + '" title="Edit"><i class="fas fa-edit"></i></button>';
                }
                rowHTML += '<button class="text-green-400 hover:text-green-300 download-btn" data-name="' + escapeHtml(name) + '" title="Download"><i class="fas fa-download"></i></button>';
                rowHTML += '<button class="text-red-400 hover:text-red-300 delete-btn" data-name="' + escapeHtml(name) + '" title="Delete"><i class="fas fa-trash"></i></button>';
                rowHTML += '</div>';
            }
            
            rowHTML += '</td>';
            
            row.innerHTML = rowHTML;
            return row;
        }

        // File operations
        async function openFileEditor(filename) {
            try {
                const url = currentPath ? '/api/file/content/' + encodeURIComponent(currentPath) + '?filename=' + encodeURIComponent(filename) : '/api/file/content?filename=' + encodeURIComponent(filename);
                const response = await fetch(url);
                const data = await response.json();
                
                if (response.ok) {
                    currentEditFile = filename;
                    document.getElementById('editor-filename').textContent = filename;
                    document.getElementById('editor-path').textContent = currentPath ? '/' + currentPath + '/' + filename : '/' + filename;
                    document.getElementById('editor-icon').className = getFileIcon(filename);
                    document.getElementById('editor-language').textContent = getLanguage(filename);
                    
                    document.getElementById('file-panel').classList.add('w-1/3');
                    document.getElementById('file-panel').classList.remove('flex-1');
                    document.getElementById('editor-panel').classList.remove('hidden');
                    
                    // Initialize or update CodeMirror
                    if (!codeEditor) {
                        codeEditor = CodeMirror(document.getElementById('editor-container'), {
                            value: data.content,
                            mode: getCodeMirrorMode(filename),
                            theme: 'monokai',
                            lineNumbers: true,
                            matchBrackets: true,
                            autoCloseBrackets: true,
                            styleActiveLine: true,
                            lineWrapping: false,
                            indentUnit: 4,
                            indentWithTabs: false
                        });
                        
                        codeEditor.on('change', updateEditorStats);
                        codeEditor.on('cursorActivity', updateCursorPosition);
                    } else {
                        codeEditor.setValue(data.content);
                        codeEditor.setOption('mode', getCodeMirrorMode(filename));
                    }
                    
                    updateEditorStats();
                    updateCursorPosition();
                    codeEditor.focus();
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                showMessage('Failed to open file', 'error');
            }
        }

        async function saveFile() {
            if (!currentEditFile || !codeEditor) return;
            
            const saveBtn = document.getElementById('save-btn');
            const originalText = saveBtn.innerHTML;
            saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Saving...';
            saveBtn.disabled = true;

            try {
                const url = currentPath ? '/api/file/save/' + encodeURIComponent(currentPath) : '/api/file/save';
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        filename: currentEditFile,
                        content: codeEditor.getValue()
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showMessage('File saved successfully', 'success');
                    await loadFiles(currentPath, false);
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                showMessage('Failed to save file', 'error');
            }

            saveBtn.innerHTML = originalText;
            saveBtn.disabled = false;
        }

        function closeEditor() {
            currentEditFile = null;
            document.getElementById('editor-panel').classList.add('hidden');
            document.getElementById('file-panel').classList.remove('w-1/3');
            document.getElementById('file-panel').classList.add('flex-1');
            
            if (codeEditor) {
                codeEditor.toTextArea();
                codeEditor = null;
            }
            document.getElementById('editor-container').innerHTML = '';
        }

        async function createFile(filename) {
            try {
                const url = currentPath ? '/api/file/create/' + encodeURIComponent(currentPath) : '/api/file/create';
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filename })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showMessage(data.message, 'success');
                    await loadFiles(currentPath);
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                showMessage('Failed to create file', 'error');
            }
        }

        async function createFolder(folderName) {
            try {
                const url = currentPath ? '/api/create_folder/' + encodeURIComponent(currentPath) : '/api/create_folder';
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ folder_name: folderName })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showMessage(data.message, 'success');
                    await loadFiles(currentPath);
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                showMessage('Failed to create folder', 'error');
            }
        }

        async function deleteFile(filename) {
            try {
                const url = currentPath ? '/api/file/delete/' + encodeURIComponent(currentPath) + '?filename=' + encodeURIComponent(filename) : '/api/file/delete?filename=' + encodeURIComponent(filename);
                const response = await fetch(url, { method: 'DELETE' });
                const data = await response.json();
                
                if (response.ok) {
                    showMessage(data.message, 'success');
                    await loadFiles(currentPath);
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                showMessage('Failed to delete file', 'error');
            }
        }

        async function createZip(files, zipName) {
            try {
                const url = currentPath ? '/api/zip/' + encodeURIComponent(currentPath) : '/api/zip';
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ files, zip_name: zipName })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showMessage(data.message, 'success');
                    await loadFiles(currentPath);
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                showMessage('Failed to create ZIP', 'error');
            }
        }

        function downloadFile(filename) {
            const url = currentPath ? '/api/download/' + encodeURIComponent(currentPath) + '?filename=' + encodeURIComponent(filename) : '/api/download?filename=' + encodeURIComponent(filename);
            
            // Create a temporary link and click it
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        async function uploadFiles(files) {
            if (!files.length) return;

            let successCount = 0;
            let errorCount = 0;

            for (const file of files) {
                const formData = new FormData();
                formData.append('file', file);
                
                try {
                    const url = currentPath ? '/api/upload/' + encodeURIComponent(currentPath) : '/api/upload';
                    const response = await fetch(url, { method: 'POST', body: formData });
                    const data = await response.json();
                    
                    if (response.ok) {
                        successCount++;
                    } else {
                        errorCount++;
                        showMessage('Failed to upload ' + file.name + ': ' + data.error, 'error');
                    }
                } catch (error) {
                    errorCount++;
                    showMessage('Failed to upload ' + file.name, 'error');
                }
            }
            
            if (successCount > 0) {
                showMessage('Uploaded ' + successCount + ' file(s) successfully', 'success');
                await loadFiles(currentPath);
            }
        }

        // UI functions
        function updateBreadcrumb(path) {
            const breadcrumb = document.getElementById('breadcrumb');
            let html = '<i class="fas fa-home text-blue-500"></i>';
            html += '<span class="text-blue-400 cursor-pointer hover:text-blue-300 px-2 py-1 rounded" onclick="loadFiles(\\'\\')">Home</span>';
            
            if (path) {
                const parts = path.split('/').filter(p => p);
                parts.forEach((part, index) => {
                    const partPath = parts.slice(0, index + 1).join('/');
                    html += '<i class="fas fa-chevron-right text-slate-500 text-xs mx-2"></i>';
                    html += '<span class="text-blue-400 cursor-pointer hover:text-blue-300 px-2 py-1 rounded" onclick="loadFiles(\\'' + escapeJs(partPath) + '\\')">' + escapeHtml(part) + '</span>';
                });
            }
            
            breadcrumb.innerHTML = html;
        }

        function updateSelectionUI() {
            const count = selectedFiles.length;
            const buttons = ['zip-btn', 'download-btn', 'delete-btn'];
            
            buttons.forEach(btnId => {
                const btn = document.getElementById(btnId);
                btn.disabled = count === 0;
                if (count === 0) {
                    btn.classList.add('opacity-50');
                } else {
                    btn.classList.remove('opacity-50');
                }
            });
            
            document.getElementById('selection-count').textContent = 
                count > 0 ? count + ' item(s) selected' : '';
        }

        function updateEditorStats() {
            if (!codeEditor) return;
            
            const content = codeEditor.getValue();
            const lines = codeEditor.lineCount();
            const chars = content.length;
            const bytes = new Blob([content]).size;
            
            document.getElementById('editor-lines').textContent = 'Lines: ' + lines;
            document.getElementById('editor-chars').textContent = 'Characters: ' + chars;
            document.getElementById('editor-size').textContent = 'Size: ' + formatSize(bytes);
        }

        function updateCursorPosition() {
            if (!codeEditor) return;
            
            const cursor = codeEditor.getCursor();
            document.getElementById('editor-cursor').textContent = 
                'Line ' + (cursor.line + 1) + ', Column ' + (cursor.ch + 1);
        }

        function showModal(title, defaultValue, callback) {
            document.getElementById('modal-title').textContent = title;
            document.getElementById('modal-input').value = defaultValue;
            document.getElementById('modal-overlay').classList.remove('hidden');
            document.getElementById('modal-input').focus();
            document.getElementById('modal-input').select();
            modalCallback = callback;
        }

        function hideModal() {
            document.getElementById('modal-overlay').classList.add('hidden');
            modalCallback = null;
        }

        function showMessage(text, type) {
            const toast = document.getElementById('message-toast');
            const content = document.getElementById('message-content');
            const icon = document.getElementById('message-icon');
            const messageText = document.getElementById('message-text');
            
            messageText.textContent = text;
            
            if (type === 'error') {
                content.className = 'p-4 rounded-lg shadow-lg border bg-red-900 border-red-700 text-red-200';
                icon.className = 'fas fa-exclamation-triangle mr-3 text-lg text-red-400';
            } else {
                content.className = 'p-4 rounded-lg shadow-lg border bg-green-900 border-green-700 text-green-200';
                icon.className = 'fas fa-check-circle mr-3 text-lg text-green-400';
            }
            
            toast.classList.remove('hidden');
            setTimeout(() => {
                toast.classList.add('hidden');
            }, 3000);
        }

        function startAutoRefresh() {
            if (autoRefreshInterval) clearInterval(autoRefreshInterval);
            autoRefreshInterval = setInterval(() => {
                if (isLoggedIn && document.getElementById('editor-panel').classList.contains('hidden')) {
                    loadFiles(currentPath, false);
                }
            }, 10000); // Changed to 10 seconds to reduce deselection issues
        }

        function stopAutoRefresh() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
            }
        }

        // Utility functions
        function getFileIcon(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const iconMap = {
                'py': 'fab fa-python text-blue-500',
                'js': 'fab fa-js text-yellow-500',
                'json': 'fas fa-code text-green-500',
                'html': 'fab fa-html5 text-orange-500',
                'css': 'fab fa-css3-alt text-blue-500',
                'txt': 'fas fa-file-alt text-gray-400',
                'md': 'fab fa-markdown text-gray-400',
                'sh': 'fas fa-terminal text-green-400',
                'bash': 'fas fa-terminal text-green-400',
                'pdf': 'fas fa-file-pdf text-red-500',
                'zip': 'fas fa-file-archive text-yellow-600',
                'rar': 'fas fa-file-archive text-yellow-600',
                '7z': 'fas fa-file-archive text-yellow-600',
                'tar': 'fas fa-file-archive text-yellow-600',
                'gz': 'fas fa-file-archive text-yellow-600',
                'jpg': 'fas fa-file-image text-purple-500',
                'jpeg': 'fas fa-file-image text-purple-500',
                'png': 'fas fa-file-image text-purple-500',
                'gif': 'fas fa-file-image text-purple-500',
                'svg': 'fas fa-file-image text-purple-500',
                'mp4': 'fas fa-file-video text-red-500',
                'avi': 'fas fa-file-video text-red-500',
                'mkv': 'fas fa-file-video text-red-500',
                'mp3': 'fas fa-file-audio text-green-500',
                'wav': 'fas fa-file-audio text-green-500',
                'flac': 'fas fa-file-audio text-green-500',
                'doc': 'fas fa-file-word text-blue-600',
                'docx': 'fas fa-file-word text-blue-600',
                'xls': 'fas fa-file-excel text-green-600',
                'xlsx': 'fas fa-file-excel text-green-600',
                'ppt': 'fas fa-file-powerpoint text-red-600',
                'pptx': 'fas fa-file-powerpoint text-red-600',
                'sql': 'fas fa-database text-orange-500'
            };
            return iconMap[ext] || 'fas fa-file text-gray-400';
        }

        function getLanguage(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const langMap = {
                'py': 'Python',
                'js': 'JavaScript',
                'json': 'JSON',
                'html': 'HTML',
                'css': 'CSS',
                'md': 'Markdown',
                'sh': 'Shell',
                'bash': 'Bash',
                'txt': 'Text',
                'xml': 'XML',
                'sql': 'SQL',
                'yml': 'YAML',
                'yaml': 'YAML',
                'ini': 'INI',
                'conf': 'Config',
                'log': 'Log'
            };
            return langMap[ext] || 'Text';
        }

        function getCodeMirrorMode(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const modeMap = {
                'py': 'python',
                'js': 'javascript',
                'json': 'application/json',
                'html': 'htmlmixed',
                'css': 'css',
                'md': 'markdown',
                'sh': 'shell',
                'bash': 'shell',
                'xml': 'xml',
                'sql': 'sql',
                'yml': 'yaml',
                'yaml': 'yaml'
            };
            return modeMap[ext] || 'text/plain';
        }

        function formatSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatDate(dateString) {
            return new Date(dateString).toLocaleString();
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function escapeJs(text) {
            return text.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");
        }
    </script>
</body>
</html>'''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=2021, debug=True)
