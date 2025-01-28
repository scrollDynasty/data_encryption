<div align="center">
  <h1>🔐 File Encryption Tool</h1>
  <p>A powerful file encryption tool with a graphical user interface</p>
  <p>
    <a href="#features">Features</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#technologies">Technologies</a> •
    <a href="#development">Development</a> •
    <a href="#license">License</a>
  </p>

  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="Python Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/status-stable-green" alt="Status">
  <a href="https://github.com/psf/black">
    <img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black">
  </a>
</div>

---

<h2 id="about">📋 About</h2>

 <img src="/img/img.png" alt="Project Banner" style="max-width: 100%; height: auto;">

<p>File Encryption Tool is a modern application for file encryption, developed with security and ease of use in mind. The program provides an intuitive graphical interface for encrypting and decrypting files using robust cryptographic algorithms.</p>

---

<h2 id="features">✨ Features</h2>

<ul>
  <li>🔒 <strong>Support for modern encryption algorithms</strong>:
    <ul>
      <li>Fernet (symmetric encryption)</li>
      <li>AES (Advanced Encryption Standard)</li>
      <li>RSA (in development)</li>
    </ul>
  </li>
  <li>🖥️ Intuitive graphical user interface</li>
  <li>📊 Progress indicator for large files</li>
  <li>📝 Detailed logging of all operations</li>
  <li>🛡️ Password validation for enhanced security</li>
  <li>🔄 Automatic file metadata preservation</li>
  <li>⚡ Optimized performance</li>
  <li>🌐 Drag-and-drop support (in development)</li>
</ul>

---

<h2 id="installation">🚀 Installation</h2>

<h3>Requirements</h3>
<ul>
  <li>Python 3.8 or higher</li>
  <li>pip (Python package manager)</li>
</ul>

<h3>Via pip (recommended)</h3>
<pre><code>pip install file-encryption
</code></pre>

<h3>From source</h3>
<pre><code>git clone https://github.com/scrollDynasty/data_encryption.git
cd data_encryption
pip install -e .
</code></pre>

<h3>Using requirements.txt</h3>
<pre><code>pip install -r requirements.txt
</code></pre>

---

<h2 id="usage">📖 Usage</h2>

<h3>Starting the application</h3>
<pre><code>python main.py
</code></pre>

<h3>Encrypting a file</h3>
<ol>
  <li>Launch the application.</li>
  <li>Click "Select File" in the "Encryption" section.</li>
  <li>Choose a file to encrypt.</li>
  <li>Enter a strong password.</li>
  <li>Select encryption algorithm.</li>
  <li>Click "Encrypt".</li>
</ol>

<h3>Decrypting a file</h3>
<ol>
  <li>Go to the "Decryption" tab.</li>
  <li>Select the encrypted file.</li>
  <li>Enter the password.</li>
  <li>Click "Decrypt".</li>
</ol>

---

<h2 id="technologies">🛠️ Technologies</h2>

<ul>
  <li><strong>Python 3.8+</strong> - main development language</li>
  <li><strong>Tkinter</strong> - graphical user interface</li>
  <li><strong>Cryptography</strong> - cryptographic operations</li>
  <li><strong>CFFI</strong> - for cryptographic library interfacing</li>
</ul>

---

<h2 id="development">🔄 Development</h2>

<p>The project is under active development. Planned improvements include:</p>
<ul>
  <li>RSA encryption support</li>
  <li>Drag-and-drop interface</li>
  <li>Multi-threaded processing for large files</li>
  <li>Cloud storage integration</li>
  <li>Dark theme interface</li>
  <li>Portable application version</li>
</ul>

<h3>Contributing</h3>
<ol>
  <li>Fork the repository.</li>
  <li>Create a feature branch.</li>
  <li>Make changes and add tests.</li>
  <li>Submit a pull request.</li>
</ol>

---

<h2 id="license">📝 License</h2>

<p>Distributed under the MIT License. See <code>LICENSE</code> for more information.</p>

---

<h2 id="authors">👥 Authors</h2>

<ul>
  <li><strong>@scrollDynasty</strong> - Lead Developer</li>
</ul>

---

<h2 id="support">📞 Support</h2>

<p>If you encounter any issues or have suggestions:</p>
<ol>
  <li>Check the existing issues.</li>
  <li>Create a new issue with a detailed description.</li>
</ol>

<p>Built with ❤️ by scrollDynasty.</p>
