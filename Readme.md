# CipherSafe

CipherSafe is a secure password manager that allows you to generate, store, and retrieve strong passwords for various websites.

## Features

- Generate strong, unique passwords for different websites
- Securely store passwords using encryption
- Retrieve stored passwords for quick access
- Regenerate passwords for existing entries
- Clean, dark-themed user interface
- Server-side encryption for added security
- Database reset functionality with enhanced security measures

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ciphersafe.git
   cd ciphersafe
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Create a `.env` file in the root directory and add your secret key:
   ```
   SECRET_KEY=your_secret_key_here
   ```

## Usage

1. Start the server:
   ```
   npm start
   ```

2. Open your web browser and navigate to `http://localhost:3000` (or the port specified in your configuration).

3. Use the interface to:
   - Generate new passwords: Enter a site name and optional length, then click "Generate"
   - Retrieve passwords: Enter a site name and click "Get"
   - Regenerate passwords: Enter a site name and click "Regenerate" (caution: this will overwrite the existing password)
   - Reset database: Click "Reset Database", type 'RESET' in the confirmation box, and click "Confirm Reset" (use with extreme caution)

## API Endpoints

- `POST /generate`: Generate a new password
- `GET /password/:siteName`: Retrieve a password for a specific site
- `PUT /regenerate/:siteName`: Regenerate a password for a specific site
- `POST /reset-database`: Reset the entire database (use with caution)

## Security

- Passwords are encrypted before being stored in the database
- The encryption key is stored in the `.env` file and should be kept secret
- Server-side encryption adds an extra layer of security
- Database reset function is protected behind a confirmation process to prevent accidental data loss

## Troubleshooting

If you encounter decryption errors, it may be due to a changed encryption key. In this case, you can reset the database:

1. Click the "Reset Database" button in the UI
2. Type 'RESET' in the confirmation box and click "Confirm Reset"
3. Re-generate all your passwords

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.