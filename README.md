# Efficient Factor Authentication ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff) ![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white) ![Azure](https://img.shields.io/badge/microsoft%20azure-0089D6?style=for-the-badge&logo=microsoft-azure&logoColor=white) ![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)

This is a Flask Application that implements unique pairs of authentication to the user depending upon their usual device and login timing.

Authentications Involved:
- Password
- Email OTP (by Azure Communication Service)
- TOTP (Time Based OTP)
- Security Question

Technologies Used:
- Azure Communication Service (Email OTP)
- MongoDB (Data and OTP storage)
- Flask (Application)

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
    SENDER_EMAIL="your_azure_communication_email"
    ```

5. Run the Flask application:
    ```bash
    flask run
    ```
    OR
    ```bach
    python app.py
    ```

## Registration and Login Functionality

- The application provides a registration page where users can create an account by providing a username, email, password, security question, and security answer.
- The login page allows users to log in with their username, password, and security answer.
- Upon successful login, users are redirected to a success page that displays a welcome message.
- The application uses MongoDB to store user information.
- The login workflow includes security question verification and OTP verification.

## Authentication Pairs and Triggers

The application uses different authentication methods based on the time of login and the device being used, as a Decision Tree. The following pairs of conditions and corresponding authentication methods are used:

- **Usual time & Known IP**: Password Only
- **Usual Time & Unknown IP**: Password + Email OTP
- **Unusual Time & Known IP**: Password + TOTP
- **Both Unusual Time & Unknown IP**: Password + Email OTP + Security Question

### Definitions

- **Usual Time**: 0800-2000 hours GMT
- **Known IP**: An IP address that has been previously used by the user to log in

## Configuring MongoDB Connection

- The MongoDB connection is configured using the `MONGO_URI` specified in the `.env` file.
- Ensure that the MongoDB URI is correctly set in the `.env` file before running the application.
- IP for network access are enabled for the database.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
