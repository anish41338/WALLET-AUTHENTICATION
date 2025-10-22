# 🧩 BlockQuest – Nonce-Based Wallet Login System

A secure Web3 authentication flow using **nonce-based login** with a **custom wallet** for the BlockQuest platform.  
This replaces passwords with cryptographic wallet signatures, ensuring **decentralized**, **secure**, and **passwordless** authentication.

---

## 🚀 Features

- 🔐 Nonce-based authentication (preventing replay attacks)
- 🪙 Wallet signature login (MetaMask / custom wallet)
- ⚡ JWT-based session management
- ⏳ Expiring + single-use nonces
- 🧱 Backend signature verification
- 🧩 Clean modular structure (Frontend + Backend)
- 🌐 Ready for production deployment

---

## 🧠 How It Works

1. **Client requests nonce** from backend.
2. **Server generates unique nonce** and stores it temporarily (unused + short expiry).
3. **Client wallet signs** the nonce message.
4. **Backend verifies** the signature and recovers wallet address.
5. **JWT issued** → client authenticated → access granted to protected routes.
6. Nonce marked as **used** → can’t be replayed.

---


## 🧾 API Endpoints

### `GET /api/nonce?address=<wallet_address>`
- Generates and returns a new nonce for a given wallet.
- Stores nonce as unused in DB (short expiry).
- **Response:**
```json
{
  "nonce": "0x9283adf123",
  "expiresIn": 600
}
```

### `POST /api/authenticate`
- Validates signature and address.
- Checks nonce status and expiry.
- Issues JWT on success.
- **Payload:**
```json
{
  "address": "0xabc123...",
  "message": "Login to BlockQuest: Nonce 0x9283...",
  "signature": "0xsignedMessage..."
}
```
- **Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR...",
  "expiresIn": 3600
}
```

---

## 🌱 Future Enhancements

- Multi-chain support (Polygon, BSC, etc.)  
- Refresh-token logic  
- Optional 2FA (wallet + email OTP)  
- Smart contract-bound login (verify token ownership)  
- Enhanced UI for wallet connect + sign message  

---

## 🧑‍💻 Author

**Anish**  
📫 [GitHub](https://github.com/yourusername)  
💼 Computer Software Student | Full Stack Developer | Blockchain Enthusiast

---

## 📄 License

This project is licensed under the **MIT License** — see the LICENSE file for details.
