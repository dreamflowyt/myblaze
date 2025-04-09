# Flask Chat Application

A real-time chat application built with Flask and Socket.IO.

## Prerequisites

- Python 3.7+
- pip
- virtualenv (recommended)

## Installation

1. Clone the repository
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file with the following variables:
   ```
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-specific-password
   SECRET_KEY=your-secret-key
   FLASK_ENV=production
   FLASK_APP=app.py
   DATABASE_URL=sqlite:///chat.db
   ```

## Running the Application

### Development
```bash
flask run
```

### Production
```bash
python wsgi.py
```

## Deployment on Render

1. Create a new account on [Render](https://render.com) if you don't have one
2. Connect your GitHub repository to Render
3. Create a new Web Service and select your repository
4. Configure the service with the following settings:
   - Environment: Python
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn wsgi:app`
5. Add the following environment variables in Render's dashboard:
   - `EMAIL_USER`: Your Gmail address
   - `EMAIL_PASS`: Your Gmail app password
   - `FLASK_ENV`: production
   - `SECRET_KEY`: (Render will generate this automatically)
6. Deploy the service

## Security Notes

1. Always use HTTPS in production
2. Keep your `.env` file secure and never commit it to version control
3. Use strong, unique passwords for all accounts
4. Regularly update dependencies

## Features

- Real-time chat using Socket.IO
- User authentication
- Email verification
- Room-based chat
- Admin dashboard
- Message history 