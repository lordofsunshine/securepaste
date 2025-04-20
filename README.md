# 💬 SecurePaste

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![Quart](https://img.shields.io/badge/quart-latest-green)
![MongoDB](https://img.shields.io/badge/mongodb-latest-green)

A secure, encrypted, and privacy-focused text sharing service for sensitive snippets with advanced security features.

## Overview

SecurePaste is a modern text sharing application designed with security and privacy in mind. Unlike traditional text sharing services, SecurePaste encrypts all content before storing it, ensuring that sensitive information remains protected. The application offers features like password protection, customizable expiration times, and raw content viewing, all wrapped in a clean, intuitive interface.

## Features

SecurePaste offers a comprehensive set of features focused on security and usability:

- **End-to-End Encryption**: All content is encrypted before being stored in the database using Fernet symmetric encryption.
- **Password Protection**: Add an extra layer of security by setting a password for your shared text.
- **Customizable Expiration**: Choose how long your content should be available (1 hour, 1 day, 1 month, 3 months, or 6 months).
- **Rate Limiting**: Protection against abuse through intelligent rate limiting on both viewing and creating content.
- **CSRF Protection**: Built-in protection against Cross-Site Request Forgery attacks.
- **Raw Content View**: Access your text in raw format for easy copying or downloading.
- **Minimalist Design**: Clean and responsive user interface that works across devices.
- **Automatic Cleanup**: Background task that removes expired content to maintain database efficiency.

## Technologies

SecurePaste is built with modern, reliable technologies:

- **Quart**: An asynchronous Python web framework compatible with the ASGI standard
- **MongoDB**: A NoSQL database for flexible and scalable data storage
- **Fernet Encryption**: Symmetric encryption to protect paste content
- **Bcrypt**: Secure password hashing for protected pastes
- **Async/Await**: Leveraging Python's asynchronous capabilities for improved performance

## Installation

### Prerequisites

- Python 3.7 or higher
- MongoDB
- pip (Python package manager)

### Setup

1. Clone the repository:

```bash
git clone https://github.com/lordofsunshine/securepaste.git
cd securepaste
```

2. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with the following variables:

```
SECRET_KEY=your_secret_key_here
ENCRYPTION_KEY=your_fernet_encryption_key_here
MONGO_URI=mongodb://localhost:27017/securepaste
SITE_URL=http://localhost:5000
```

To generate a secure Fernet key, you can use:

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

5. Start the application:

```bash
python app.py
```

The application will be available at `http://localhost:5000`.

## Deployment

For production deployment, it's recommended to use a production ASGI server such as Hypercorn or Uvicorn. You should also ensure that:

- HTTPS is enabled
- Environment variables are securely set
- A production MongoDB instance is used
- Rate limiting is properly configured for your expected traffic

Example deployment with Hypercorn:

```bash
pip install hypercorn
hypercorn app:app --bind 0.0.0.0:8000
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
