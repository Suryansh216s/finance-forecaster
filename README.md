# Finance Forecaster

Finance Forecaster is a simple web application for tracking income, expenses and financial goals. It provides a dashboard where authenticated users can record transactions and monitor their progress.

## Prerequisites

- **Python 3.10+** - see `.python-version` for the version used in development.
- **MySQL** server running and accessible with credentials configured in the application.
- It is recommended to create and activate a virtual environment before installing dependencies.

Install Python packages with:

```bash
pip install -r requirements.txt
```

## Environment variables

Create a `.env` file in the project root or export the following variables in your shell:

- `FLASK_APP` – entry point of the application (default `app.py`).
- `FLASK_ENV` – set to `development` for debug mode.
- `GEMINI_API_KEY` – API key for any AI powered features.
- `DATABASE_URL` – connection string for your MySQL instance (e.g. `mysql://user:pass@localhost/finance_forecaster`).

These values are used when running the app with Flask or Gunicorn.

## Running the application

After installing dependencies and configuring environment variables, initialise the database and start the development server:

```bash
flask run
```

For production deployments the provided `Procfile` runs the app with Gunicorn:

```bash
gunicorn app:app
```

The server will be available at `http://localhost:5000` by default.
