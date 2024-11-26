# Encrypted Communication App 📡🔐

Welcome to the **Encrypted Communication App**, where messages are safe, secure, and fun to send! This project demonstrates secure communication between a client and a server using **socket programming** and two encryption methods like **AES** and **RSA**. Whether you're encrypting like a pro or just sending plain text, this app has your back. 🚀
This was a homework in the ISS course

---

## 🎉 Features
- **Flexible Encryption**: Choose between:
  - `AES` for speed 🔥
  - `RSA` for security 🔒
  - Or no encryption, because YOLO 🤷‍♂️
- **Seamless Communication**: Connect a client and server effortlessly on your local machine.
- **Dynamic Key Exchange**: RSA public keys and AES keys/IVs are exchanged securely. 
- **Interactive UI**: Fun and colorful prompts using `Colorama`.

---

## 🛠️ Requirements
Before you dive in, make sure you have the following installed:
- **Python 3.8+**
- Required libraries:
  - `colorama`
  - `cryptography` (for AES and RSA)

Install dependencies with:
```bash
pip install colorama cryptography
```

---

## 🚀 Getting Started

### 1️⃣ Clone the Repo
```bash
git clone https://github.com/Noore573/Homework.git
cd Homework
```

### 2️⃣ Run the Server
Start the server to listen for incoming connections:
```bash
python server.py
```

### 3️⃣ Run the Client
In another terminal, start the client to initiate communication:
```bash
python client.py
```

---

## 🎮 How to Use

### **Client Side** 👨‍💻
- Type your message and hit `Enter`.
- Choose your encryption method:
  1. AES 🔒
  2. RSA 🔐
  3. No encryption 🤔
- Watch your message get encrypted and sent to the server in style!

### **Server Side** 🛠️
- Sit back and relax while the server:
  - Receives encrypted messages.
  - Decrypts and displays them.
  - Stays awesome. 😎

---

## 🔍 Encryption Methods
### Advanced Encryption Standard (AES)
- Symmetric encryption.
- Super fast, uses a shared **key** and **IV**.

### Rivest-Shamir-Adleman (RSA)
- Asymmetric encryption.
- Public key for encryption, private key for decryption.

### No Encryption (Plain Text)
- For when you just need to keep things simple (or you're feeling bold).

---

## 🌈 Colors Make Everything Better
We’ve used **Colorama** to add some spice:
- **Green** for prompts.
- **Blue** for encryption info.
- **Cyan** for decrypted messages.

Feel free to add more colors and make it even more exciting! 🎨

---

## 🧙‍♂️ Pro Tip
- Want to test locally? The default `host` is `127.0.0.1` (localhost).
- Wanna go public? change the ip_address to match your device
- You can customize the port in the code (`port = 5002`).


---

## 🛡️ Security Notes
- AES and RSA are strong encryption standards, but ensure to:
  - Use longer RSA keys (2048+ bits) for production.
  - Keep your private key safe!
- For a real-world app, consider SSL/TLS for secure channel setup.

---

## 🚀 Ready to Encrypt?
Why wait? Dive into secure messaging now and send your first **encrypted hello!**

Made with ❤️ and some cryptographic magic. 🪄