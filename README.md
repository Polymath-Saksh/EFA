# Flask Application with Registration and Login

This is a basic Flask application with registration and login pages, redirecting to a success page on login. It uses MongoDB for storage.

## Setup and Running the Application

1. Clone the repository:
    ```bash
    git clone https://github.com/Polymath-Saksh/EFA.git
    cd EFA
    ```

2. Create a virtual environment and activate it:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

4. Create a `.env` file in the root directory of the project and add the following lines with your MongoDB URI and Azure Communication Email connection string:
    ```bash
    MONGO_URI="your_mongodb_uri"
    AZURE_COMMUNICATION_CONNECTION_STRING="your_azure_communication_connection_string"
    ```

5. Run the Flask application:
    ```bash
    flask run
    ```

## Registration and Login Functionality

- The application provides a registration page where users can create an account by providing a username, email, password, security question, and security answer.
- The login page allows users to log in with their username, password, and security answer.
- Upon successful login, users are redirected to a success page that displays a welcome message.
- The application uses MongoDB to store user information.
- The login workflow includes security question verification and OTP verification.

## Configuring MongoDB Connection

- The MongoDB connection is configured using the `MONGO_URI` specified in the `.env` file.
- Ensure that the MongoDB URI is correctly set in the `.env` file before running the application.
