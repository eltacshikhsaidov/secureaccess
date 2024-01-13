# Admin Controller

## Endpoints

### 1. Get Environment Information

- **Endpoint**: `/v1/admin/application/environment`
- **Method**: GET
- **Produces**: application/json
- **Authorization**: Requires 'ADMIN' authority
- **Description**: Retrieves information about the application environment.

### 2. Get Users

- **Endpoint**: `/v1/admin/users`
- **Method**: GET
- **Produces**: application/json
- **Authorization**: Requires 'ADMIN' authority
- **Parameters**:
  - `status` (optional, default: ACTIVE) - User status (e.g., ACTIVE, INACTIVE)
  - `locked` (optional, default: false) - Filter users by locked status
  - `enabled` (optional, default: true) - Filter users by enabled status
- **Description**: Retrieves a list of users based on the specified criteria.

### 3. Get Emails

- **Endpoint**: `/v1/admin/emails`
- **Method**: GET
- **Produces**: application/json
- **Authorization**: Requires 'ADMIN' authority
- **Parameters**:
  - `status` (optional, default: SENT) - Email status (e.g., SENT, PENDING)
- **Description**: Retrieves a list of emails based on the specified status.

# Authentication Controller

### 1. Register

- **Endpoint**: `/v1/auth/register`
- **Method**: POST
- **Consumes**: application/json
- **Parameters**:
  - `request` (RequestBody) - User registration details
- **Description**: Registers a new user by processing the provided registration details.

### 2. Login

- **Endpoint**: `/v1/auth/login`
- **Method**: POST
- **Consumes**: application/json
- **Parameters**:
  - `request` (RequestBody) - User login credentials
- **Description**: Handles user authentication by validating login credentials.

### 3. Confirm Token

- **Endpoint**: `/v1/auth/confirm`
- **Method**: GET
- **Parameters**:
  - `token` (RequestParam) - Confirmation token
- **Description**: Confirms the validity of a given token, typically used for email confirmation.

### 4. Forgot Password

- **Endpoint**: `/v1/auth/forgot-password`
- **Method**: POST
- **Consumes**: application/json
- **Parameters**:
  - `request` (RequestBody) - Request details for password reset
- **Description**: Initiates the process of resetting a user's password by sending a reset link.

### 5. Reset Password

- **Endpoint**: `/v1/auth/reset-password`
- **Method**: POST
- **Consumes**: application/json
- **Parameters**:
  - `request` (RequestBody) - New password details
- **Description**: Resets the user's password based on the provided reset details.

### 6. Verify Device

- **Endpoint**: `/v1/auth/verify-device`
- **Method**: GET
- **Parameters**:
  - `token` (RequestParam) - Device verification token
- **Description**: Verifies the authenticity of a device by validating the provided token.

