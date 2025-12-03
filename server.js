// server.js

// -----------------------------------------------------
// 1. CONFIGURATION & SETUP
// -----------------------------------------------------

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // You are using bcryptjs, which is fine.
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
require('dotenv').config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 3000;

// Trust the first proxy in front of the app. This is required for express-rate-limit
// to work correctly when hosted on a platform like Render.
app.set('trust proxy', 1);

// Middleware
app.use(cors());
app.use(express.json());

// Set up static file serving for all public files (CSS, JS, images, HTML).
// This should come early so that requests for static assets are handled quickly.
app.use(express.static(path.join(__dirname, 'public')));

// Database Connection
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
    throw new Error('FATAL ERROR: MONGO_URI is not defined in your .env file.');
}

mongoose.connect(MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Nodemailer Transporter Setup
// Read SMTP configuration from environment variables so we can support
// different providers (smtp2go, gmail, cPanel, etc.).
// Preferred env vars:
//  - SMTP_HOST (default: mail.smtp2go.com)
//  - SMTP_PORT (default: 587)
//  - SMTP_SECURE ("true" to use TLS, default: false)
//  - SMTP_USER or EMAIL_USER
//  - SMTP_PASS or EMAIL_PASS or SMTP2GO_PASS
const smtpHost = process.env.SMTP_HOST || 'mail.smtp2go.com';
const smtpPort = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 2525;
const smtpSecure = (process.env.SMTP_SECURE === 'true');
const smtpUser = process.env.SMTP_USER || process.env.EMAIL_USER;
const smtpPass = process.env.SMTP_PASS || process.env.EMAIL_PASS || process.env.SMTP2GO_PASS;

const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: {
        user: smtpUser,
        pass: smtpPass
    }
});

// Verify transporter configuration at startup so misconfiguration is logged early
transporter.verify((err, success) => {
    if (err) {
        console.error('Email transporter configuration error:', err);
    } else {
        console.log('Email transporter is configured and ready.');
    }
});


// -----------------------------------------------------
// 2. MONGOOSE MODELS
// -----------------------------------------------------

// --- User Model
const User = require('./models/user');

// --- Exclusion Model
const ExclusionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    studentId: { type: mongoose.Schema.Types.ObjectId, required: true },
    date: { type: Date, required: true },
});

ExclusionSchema.index({ userId: 1, studentId: 1, date: 1 }, { unique: true });

const Exclusion = mongoose.model('Exclusion', ExclusionSchema);

// --- Message Model
const MessageSchema = new mongoose.Schema({
    conversationId: { type: String, required: true, index: true }, // Will be rider's userId or 'global'
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    senderName: { type: String, required: true },
    content: { type: String, required: true },
    groupId: { type: String }, // optional group id for announcements to track bulk operations
    timestamp: { type: Date, default: Date.now },
    isRead: { type: Boolean, default: false } // To track if a message has been seen by the secretary
});
const Message = mongoose.model('Message', MessageSchema);


// --- Temporary Address Model
const TemporaryAddressSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    pickupAddress: { type: String, required: true }, // Renamed from 'address'
    dropoffAddress: { type: String }, // New field
    instructions: { type: String }, // New field
    effectiveDate: { type: Date, required: true },
});
TemporaryAddressSchema.index({ userId: 1, effectiveDate: 1 }, { unique: true });
const TemporaryAddress = mongoose.model('TemporaryAddress', TemporaryAddressSchema);

// --- Notification Model
const NotificationSchema = new mongoose.Schema({
    type: { type: String, enum: ['PermanentAddressChange', 'TemporaryAddress', 'ServiceSuspension'], required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userName: { type: String, required: true },
    content: { type: String, required: true },
    effectiveDate: { type: Date }, // For temporary changes
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', NotificationSchema);

// --- Invite Model
const Invite = require('./models/Invite');
// --- Non-Operation Model (calendar)
const NonOperation = require('./models/NonOperation');

// -----------------------------------------------------
// 3. CORE ROUTES & STATIC FILE HANDLERS
// -----------------------------------------------------

// --- Authentication Middleware ---
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expects "Bearer TOKEN"

    if (token == null) {
        return res.status(401).json({ message: 'No token provided.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        try {
            const user = await User.findById(decoded.id).select('-password'); // Fetch user from DB
            if (!user || user.isDeleted) {
                return res.status(403).json({ message: 'User not found or deactivated.' });
            }
            req.user = user; // Attach the full, fresh user object to the request
            next();
        } catch (error) {
            console.error('Authentication error:', error);
            return res.status(500).json({ message: 'Server error during authentication.' });
        }
    });
};

// --- Authorization Middleware ---
const authorize = (roles = []) => {
    // Ensure roles is an array
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return (req, res, next) => {
        // If the user is an admin, they are always authorized.
        if (req.user && req.user.role === 'admin') { // This check now uses the fresh user object
            return next();
        }

        // For other users, check if their role is in the allowed list.
        if (!req.user || (roles.length > 0 && !roles.includes(req.user.role))) {
            return res.status(403).json({ message: 'Forbidden: You do not have permission to perform this action.' });
        }
        next();
    };
};


/**
 * POST /api/register
 * Creates new user (rider, driver, or secretary)
 */
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, role, parentName, phoneNumber, address, students } = req.body;

        // Hash password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            role,
            parentName: parentName, // Now saved for all roles
            phoneNumber: role === 'rider' ? phoneNumber : undefined,
            address: role === 'rider' ? address : undefined,
            students: role === 'rider' ? students : [],
            passwordHistory: [hashedPassword] // Add first password to history
        });

        await newUser.save();
        res.status(201).send({ message: `${role} user created successfully.` });

    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).send('Username or Email already exists.');
        }
        console.error('Registration error:', error);
        res.status(500).send('Error creating user.');
    }
});


// Rate Limiter for login attempts to prevent brute-force attacks
const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 5, // Limit each IP to 5 FAILED login requests per windowMs
	message: { message: 'Too many failed login attempts from this IP, please try again after 15 minutes' },
	standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    skipSuccessfulRequests: true // Don't count successful logins
});

// Rate Limiter for forgot-password to prevent email spam attacks
const forgotPasswordLimiter = rateLimit({
	windowMs: 60 * 60 * 1000, // 1 hour
	max: 5, // Limit each IP to 5 password reset requests per hour
	message: { message: 'Too many password reset attempts from this IP, please try again after 1 hour' },
	standardHeaders: true,
	legacyHeaders: false,
	skipSuccessfulRequests: false // Count all requests (don't skip successes)
});


/**
 * POST /api/login
 * Handles user authentication for all roles
 */
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        // Prevent soft-deleted users from logging in
        if (user && user.isDeleted) {
            return res.status(401).json({ message: 'This account has been deactivated.' });
        }

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).send('Invalid credentials.');
        }

        // --- Create JWT ---
        const token = jwt.sign(
            { id: user._id, role: user.role, name: user.parentName || user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1d' } // Token expires in 1 day
        );

        res.status(200).json({
            id: user._id,
            role: user.role,
            name: user.parentName || user.username,
            token: token // Send token to client
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// -----------------------------------------------------
// 3.2 INVITE & SIGN-UP ROUTES
// -----------------------------------------------------

/**
 * POST /api/invites
 * Creates a new invite and sends an email to the prospective rider.
 */
app.post('/api/invites', authenticateToken, authorize(['admin', 'secretary', 'driver']), async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }

    try {
        // Check if a user with this email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'A user with this email already exists.' });
        }

    // Determine invite role. Default to 'rider'. Allow admin invites only from admin users.
    const requestedRole = (req.body.role || 'rider').toLowerCase();
    const allowedRoles = ['rider', 'secretary', 'driver'];
    if (req.user && req.user.role === 'admin') allowedRoles.push('admin');
    const inviteRole = allowedRoles.includes(requestedRole) ? requestedRole : 'rider';

    // Create a new invite token and save it with role
    const invite = new Invite({ email, role: inviteRole });
    await invite.save();
    console.log(`Created invite for ${email} with role=${inviteRole} token=${invite.token}`);

        // Use the BASE_URL from environment variables for the link
        const signUpLink = `${process.env.BASE_URL}/signup.html?token=${invite.token}`;

        // Send the email. If sending fails, remove the saved invite so we don't leave
        // a token that the user can't use.
        try {
            const fromAddress = process.env.FROM_EMAIL || process.env.EMAIL_USER || process.env.SMTP_USER || 'donotreply@churchandfam.com';
            console.log(`Sending invite email from: ${fromAddress} to: ${email}`);

            await transporter.sendMail({
                from: fromAddress,
                envelope: { from: fromAddress, to: email },
                to: email,
                subject: 'You are invited to join RouteKeeper',
                html: `<p>Please click the following link to create your RouteKeeper account:</p>
                       <p><a href="${signUpLink}">${signUpLink}</a></p>
                       <p>This link will expire in 7 days.</p>`
            });

            res.status(201).json({ message: `An invite has been sent to ${email}.` });

        } catch (mailErr) {
            // Log the mail error for diagnosis (include the from we attempted)
            console.error('Error sending invite email:', mailErr);
            console.error('Invite email attempted from:', process.env.FROM_EMAIL, process.env.EMAIL_USER, process.env.SMTP_USER);

            // Attempt to delete the invite we just created to avoid orphaned tokens
            try {
                await Invite.deleteOne({ _id: invite._id });
            } catch (delErr) {
                console.error('Error deleting invite after failed email send:', delErr);
            }

            return res.status(500).json({ message: 'Failed to send invite email. Please try again later.' });
        }

    } catch (error) {
        // Handle potential unique constraint errors on the Invite model for the email
        if (error.code === 11000) {
            return res.status(409).json({ message: 'An invite for this email has already been sent.' });
        }
        console.error('Error creating invite:', error);
        res.status(500).json({ message: 'Server error while creating invite.' });
    }
});

/**
 * GET /api/invites/:token
 * Verifies an invite token for the sign-up page.
 */
app.get('/api/invites/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const invite = await Invite.findOne({
            token: token,
            isUsed: false,
            expiresAt: { $gt: new Date() }
        });

        if (!invite) {
            return res.status(404).json({ message: 'This invite link is invalid or has expired.' });
        }

        res.status(200).json({ email: invite.email, role: invite.role });
    } catch (error) {
        console.error('Error verifying invite token:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

/**
 * POST /api/signup-from-invite
 * Creates a new rider account from a valid invite.
 */
app.post('/api/signup-from-invite', async (req, res) => {
    const { token, parentName, username, password, address } = req.body;

    try {
        const invite = await Invite.findOne({
            token: token,
            isUsed: false,
            expiresAt: { $gt: new Date() }
        });

        if (!invite) {
            return res.status(400).json({ message: 'This invite link is invalid or has expired.' });
        }

    const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            email: invite.email,
            password: hashedPassword,
            role: invite.role || 'rider',
            parentName: parentName,
            address: invite.role === 'rider' ? address : undefined,
            passwordHistory: [hashedPassword]
        });
        await newUser.save();
    console.log(`Created user from invite: ${newUser.email} role=${newUser.role} id=${newUser._id}`);

        invite.isUsed = true;
        await invite.save();

        res.status(201).json({ message: 'Account created successfully! You will be redirected to log in.' });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ message: 'Username or Email already exists.' });
        }
        console.error('Error during sign-up from invite:', error);
        res.status(500).json({ message: 'Error creating account.' });
    }
});

// -----------------------------------------------------
// 3.5 PASSWORD RESET ROUTES
// -----------------------------------------------------

/**
 * POST /api/forgot-password
 * Handles the initial request, generates a token, and sends a reset email.
 */
app.post('/api/forgot-password', forgotPasswordLimiter, async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required.' });

    try {
        const user = await User.findOne({ email });

        // Always send a generic success message to prevent user enumeration
        if (!user) {
            return res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenExpiry = new Date(Date.now() + 3600000); // Token expires in 1 hour

        await User.updateOne(
            { _id: user._id },
            { $set: { passwordResetToken: resetToken, passwordResetExpires: tokenExpiry } }
        );
        console.log(`Password reset token generated for user: ${user.email}`);

        // Use the BASE_URL from environment variables for the link
        const resetURL = `${process.env.BASE_URL}/reset-password.html?token=${resetToken}`;

        await transporter.sendMail({
            to: user.email,
            from: process.env.FROM_EMAIL || process.env.EMAIL_USER || process.env.SMTP_USER || 'donotreply@churchandfam.com',
            envelope: { from: process.env.FROM_EMAIL || process.env.EMAIL_USER || process.env.SMTP_USER || 'donotreply@churchandfam.com', to: user.email },
            subject: 'Password Reset Request for RouteKeeper',
            html: `<p>You requested a password reset. Please click the following link to set a new password:</p><p><a href="${resetURL}">${resetURL}</a></p><p>This link will expire in one hour.</p><p>If you did not request this, please ignore this email.</p>`
        });

        res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });

    } catch (err) {
        console.error('Error in /forgot-password:', err);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});

/**
 * POST /api/reset-password
 * Handles the final password reset action, validates the token, and updates the password.
 */
app.post('/api/reset-password', async (req, res) => {
    const { token, password } = req.body;

    if (!token || !password) {
        return res.status(400).json({ message: 'Token and new password are required.' });
    }

    // Validate password length (minimum 8 characters)
    if (password.length < 8) {
        return res.status(400).json({ message: 'Password must be at least 8 characters long.' });
    }

    try {
        // Find user by token, and ensure the token has not expired
        const user = await User.findOne({
            passwordResetToken: token,
            passwordResetExpires: { $gt: new Date() } // Check if expiry date is in the future
        });

        if (!user) {
            return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
        }

        // Check if the new password has been used before
        for (const oldPasswordHash of user.passwordHistory) {
            const isMatch = await bcrypt.compare(password, oldPasswordHash);
            if (isMatch) {
                return res.status(409).json({ message: 'Cannot reuse a previous password. Please choose a new one.' });
            }
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update the user's password and remove the reset token fields
        user.password = hashedPassword;
        user.passwordHistory.push(hashedPassword);
        // Optional: Limit the history to the last 5 passwords
        if (user.passwordHistory.length > 5) {
            user.passwordHistory.shift(); // Remove the oldest password
        }
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();
        console.log(`Password successfully reset for user: ${user.email}`);

        res.status(200).json({ message: 'Your password has been successfully reset. You will be redirected to the login page shortly.' });

    } catch (err) {
        console.error('Error in /reset-password:', err);
        res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});


/**
 * GET /api/user/:id
 * Fetches single user data (used by rider dashboard)
 */
app.get('/api/user/:id', authenticateToken, async (req, res) => {
    try {
        // SECURITY FIX: A rider can only fetch their own data. Admin/staff can fetch any.
        if (req.user.role === 'rider' && req.user._id.toString() !== req.params.id) {
            return res.status(403).json({ message: 'Forbidden: You can only access your own data.' });
        }

        const user = await User.findById(req.params.id).select('-password -passwordHistory');
        if (!user) {
            return res.status(404).send('User not found.');
        }
        res.status(200).json(user);
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).send('Internal server error.');
    }
});

/**
 * PUT /api/user/:id/address
 * Updates a user's permanent address and creates a notification.
 */
app.put('/api/user/:id/address', authenticateToken, authorize('rider'), async (req, res) => {
    try {
        const { address } = req.body;
        // SECURITY FIX: Ensure the user is only updating their own address by using the ID from the token
        const user = await User.findById(req.user._id);
        
        if (!user) {
            return res.status(404).send('User not found.');
        }

        user.address = address;
        await user.save();

        // Create a notification for this change
        const notification = new Notification({
            type: 'PermanentAddressChange',
            userId: user._id,
            userName: user.parentName,
            content: `Updated permanent address to: ${address}`
        });
        await notification.save();

        res.status(200).json({ message: 'Address updated successfully.', address: user.address });

    } catch (error) {
        console.error('Error updating address:', error);
        res.status(500).send('Internal server error.');
    }
});





/**
 * GET /api/users?role=rider
 * Fetches all users of a specific role (used by driver/secretary dashboard)
 */
app.get('/api/users', authenticateToken, authorize(['admin', 'secretary', 'driver']), async (req, res) => {
    try {
        const { role } = req.query;
        const query = { isDeleted: { $ne: true } };
        if (role) {
            query.role = role;
        }
        // If no role is specified, it will find all users that are not deleted.
        const users = await User.find(query).sort({ role: 1, parentName: 1 });
        res.status(200).json(users);
    } catch (error) {
        console.error('Error fetching users by role:', error);
        res.status(500).send('Internal server error.');
    }
});

/**
 * GET /api/users/deleted
 * Fetches all soft-deleted rider accounts.
 */
app.get('/api/users/deleted', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const deletedUsers = await User.find({
            isDeleted: true,
            deletionDate: { $gte: thirtyDaysAgo } // Only show users deleted within the last 30 days
        }).sort({ deletionDate: -1 });
        res.status(200).json(deletedUsers);
    } catch (error) {
        console.error('Error fetching deleted users:', error);
        res.status(500).send('Internal server error.');
    }
});

/**
 * DELETE /api/users/:id
 * Soft-deletes a user by setting the isDeleted flag.
 */
app.delete('/api/users/:id', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(
            req.params.id,
            { $set: { isDeleted: true, deletionDate: new Date() } },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({ message: `User '${user.parentName}' has been deactivated. They can be restored for 30 days.` });

    } catch (error) {
        console.error('Error soft-deleting user:', error);
        res.status(500).json({ message: 'An error occurred during deactivation.' });
    }
});

/**
 * PUT /api/users/:id/restore
 * Restores a soft-deleted user.
 */
app.put('/api/users/:id/restore', authenticateToken, authorize('admin'), async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(
            req.params.id,
            {
                $set: { isDeleted: false },
                $unset: { deletionDate: "" } // Remove the deletion date
            },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({ message: `User '${user.parentName}' has been successfully restored.` });

    } catch (error) {
        console.error('Error restoring user:', error);
        res.status(500).json({ message: 'An error occurred during restoration.' });
    }
});

/**
 * GET /api/exclusions?userId=...&date=...
 * Fetches exclusions for a specific rider and date (used by rider dashboard)
 */
app.get('/api/exclusions', authenticateToken, async (req, res) => {
    try {
        const { userId, date } = req.query;
        if (!date) {
            return res.status(400).send('Missing query parameter (date).');
        }
        // SECURITY FIX: A rider can only fetch their own exclusions.
        if (req.user.role === 'rider' && req.user._id.toString() !== userId) {
            return res.status(403).json({ message: 'Forbidden: You can only access your own data.' });
        }

        const exclusions = await Exclusion.find({ userId: userId, date: new Date(date) });
        
        const excludedIds = exclusions.map(e => e.studentId.toString());
        res.status(200).json(excludedIds);
    } catch (error) {
        console.error('Error fetching rider exclusions:', error);
        res.status(500).send('Internal server error.');
    }
});


/**
 * GET /api/exclusions/all?date=...
 * Fetches all exclusions for a date (used by driver/secretary dashboard)
 */
app.get('/api/exclusions/all', authenticateToken, authorize(['admin', 'secretary', 'driver']), async (req, res) => {
    try {
        const { date } = req.query;
        if (!date) {
            return res.status(400).send('Missing query parameter (date).');
        }

        const exclusions = await Exclusion.find({ date: new Date(date) });
        res.status(200).json(exclusions);
    } catch (error) {
        console.error('Error fetching all exclusions:', error);
        res.status(500).send('Internal server error.');
    }
});


/**
 * POST /api/rider/cancel
 * Marks a student as "Not Coming" (creates an exclusion document)
 */
app.post('/api/rider/cancel', authenticateToken, authorize('rider'), async (req, res) => {
    try {
        const { studentId, date } = req.body;
        
        const newExclusion = new Exclusion({
            userId: req.user._id, // SECURITY FIX: Use authenticated user ID
            studentId,
            date: new Date(date),
        });

        await newExclusion.save();
        res.status(201).send('Exclusion recorded.');

    } catch (error) {
        if (error.code === 11000) {
            return res.status(200).send('Exclusion already exists.');
        }
        console.error('Error cancelling ride:', error);
        res.status(500).send('Error recording exclusion.');
    }
});


/**
 * POST /api/rider/re-add
 * Re-adds a student (deletes the exclusion document)
 */
app.post('/api/rider/re-add', authenticateToken, authorize('rider'), async (req, res) => {
    try {
        const { studentId, date } = req.body;

        const result = await Exclusion.deleteOne({
            userId: req.user._id, // SECURITY FIX: Use authenticated user ID
            studentId,
            date: new Date(date),
        });

        if (result.deletedCount === 0) {
            return res.status(404).send('Exclusion not found.');
        }
        
        res.status(200).send('Exclusion removed. Student re-added.');

    } catch (error) {
        console.error('Error re-adding ride:', error);
        res.status(500).send('Error removing exclusion.');
    }
});

// -----------------------------------------------------
// 4. TEMPORARY ADDRESS & NOTIFICATION ROUTES
// -----------------------------------------------------

/**
 * POST /api/temporary-address
 * Sets a temporary address for a user for a specific date.
 */
app.post('/api/temporary-address', authenticateToken, authorize('rider'), async (req, res) => {
    try {
        const { pickupAddress, dropoffAddress, instructions, effectiveDate } = req.body;
        if (!pickupAddress) {
            return res.status(400).json({ message: 'Temporary pickup address is required.' });
        }

        // Use `findOneAndUpdate` with `upsert` to create or update the temporary address
        const tempAddress = await TemporaryAddress.findOneAndUpdate(
            { userId: req.user._id, effectiveDate: new Date(effectiveDate) }, // SECURITY FIX: Use authenticated user ID
            { pickupAddress, dropoffAddress, instructions }, // Update these fields
            { new: true, upsert: true }
        );

        // Use the user object from the token
        const user = req.user;
        if (user) {
            // Add to history and keep only the last 3 unique addresses
            const history = [...new Set([pickupAddress, ...user.temporaryAddressHistory])].slice(0, 3);
            user.temporaryAddressHistory = history;
            await user.save();
        }
        // Create a notification
        const notification = new Notification({
            type: 'TemporaryAddress',
            userId: user._id,
            userName: user.parentName,
            content: `Set temporary pickup for ${new Date(effectiveDate).toLocaleDateString()}: ${pickupAddress}` +
                     (dropoffAddress ? ` (Dropoff: ${dropoffAddress})` : '') +
                     (instructions ? ` (Instructions: ${instructions})` : ''),
            effectiveDate: new Date(effectiveDate)
        });
        await notification.save();

        res.status(201).json({ message: 'Temporary address set.', tempAddress });

    } catch (error) {
        console.error('Error setting temporary address:', error);
        res.status(500).send('Internal server error.');
    }
});

/**
 * GET /api/temporary-address?date=...
 * Fetches all temporary addresses for a specific date. Used by driver/secretary.
 */
app.get('/api/temporary-address', authenticateToken, async (req, res) => {
    try {
        const { date, userId } = req.query;
        if (!date) {
            return res.status(400).send('Missing query parameter (date).');
        }

        const query = { effectiveDate: new Date(date) };
        if (userId) {
            // SECURITY FIX: A rider can only fetch their own temporary address.
            if (req.user.role === 'rider' && req.user._id.toString() !== userId) {
                return res.status(403).json({ message: 'Forbidden: You can only access your own data.' });
            }
            query.userId = userId;
        }

        const tempAddresses = await TemporaryAddress.find(query);

        // If a specific user's address was requested, return the single object or null.
        // Otherwise, return the array for the driver/secretary views.
        const responseData = userId ? (tempAddresses[0] || null) : tempAddresses;
        res.status(200).json(responseData);

    } catch (error) {
        console.error('Error fetching temporary addresses:', error);
        res.status(500).send('Internal server error.');
    }
});

// -----------------------------------------------------
// 4.1 CALENDAR - SUNDAYS & NON-OPERATION MANAGEMENT
// -----------------------------------------------------

/**
 * Helper: generate list of Sunday dates for the next N months grouped by month
 */
function getSundaysByMonth(months = 6) {
    const result = [];
    const today = new Date();
    // Start from the beginning of current month
    let cursor = new Date(today.getFullYear(), today.getMonth(), 1);

    for (let m = 0; m < months; m++) {
        const year = cursor.getFullYear();
        const month = cursor.getMonth();
        // find first day of month
        const firstOfMonth = new Date(year, month, 1);
        const sundays = [];

        // iterate days in month
        for (let d = 1; d <= 31; d++) {
            const dt = new Date(year, month, d);
            if (dt.getMonth() !== month) break; // passed month
            if (dt.getDay() === 0) { // Sunday
                sundays.push(new Date(dt.getFullYear(), dt.getMonth(), dt.getDate()));
            }
        }

        result.push({ year, month, sundays });
        // move to next month
        cursor = new Date(year, month + 1, 1);
    }

    return result;
}

/**
 * GET /api/calendar/sundays?months=6
 * Returns the next N months' Sundays and whether they are marked non-operational.
 */
app.get('/api/calendar/sundays', authenticateToken, authorize(['admin', 'secretary']), async (req, res) => {
    try {
        const months = parseInt(req.query.months || '6', 10);
        const monthsData = getSundaysByMonth(months);

        // Build date range to query non-operation docs
        const startDate = monthsData[0].sundays.length ? monthsData[0].sundays[0] : new Date();
        const lastMonth = monthsData[monthsData.length - 1];
        const lastSundays = lastMonth.sundays;
        const endDate = lastSundays.length ? lastSundays[lastSundays.length - 1] : new Date();

        const nonOps = await NonOperation.find({ date: { $gte: startDate, $lte: endDate } });
        const nonOpMap = {};
        nonOps.forEach(n => {
            const key = new Date(n.date).toISOString().slice(0,10);
            nonOpMap[key] = { id: n._id, occasion: n.occasion, groupId: n.groupId };
        });

        const response = monthsData.map(m => ({
            year: m.year,
            month: m.month,
            monthLabel: new Date(m.year, m.month, 1).toLocaleString('default', { month: 'short' }),
            sundays: m.sundays.map(d => {
                const iso = d.toISOString().slice(0,10);
                const mapped = nonOpMap[iso];
                return {
                    date: d.toISOString(),
                    day: d.getDate(),
                    monthAbbr: d.toLocaleString('default', { month: 'short' }),
                    isNonOp: Boolean(mapped),
                    occasion: mapped ? mapped.occasion : undefined,
                    id: mapped ? mapped.id : undefined
                };
            })
        }));

        res.status(200).json(response);
    } catch (error) {
        console.error('Error fetching calendar sundays:', error);
        res.status(500).json({ message: 'Error fetching calendar.' });
    }
});

/**
 * POST /api/calendar/nonop
 * Body: { date: 'YYYY-MM-DD', occasion: '...' }
 * Marks a single Sunday as non-operational and creates a global announcement.
 */
app.post('/api/calendar/nonop', authenticateToken, authorize(['admin', 'secretary']), async (req, res) => {
    try {
        const { date, occasion } = req.body;
        if (!date) return res.status(400).json({ message: 'Date is required.' });

        const d = new Date(date);
        d.setHours(0,0,0,0);

        // Upsert non-operation for this date and ensure it has a groupId so announcements are dedupable
        let existing = await NonOperation.findOne({ date: d });
        let groupId;
        if (existing) {
            existing.occasion = occasion || existing.occasion;
            if (!existing.groupId) existing.groupId = crypto.randomBytes(8).toString('hex');
            groupId = existing.groupId;
            await existing.save();
        } else {
            groupId = crypto.randomBytes(8).toString('hex');
            await NonOperation.create({ date: d, occasion: occasion || '', createdBy: req.user._id, groupId });
        }

        // Create a single global message to notify riders (include gid token to avoid duplicates)
    const formatted = d.toLocaleDateString();
    const content = `Service Suspension: Bus will NOT run on ${formatted}` + (occasion ? ` — ${occasion}` : '');
    const announcement = new Message({ conversationId: 'global', senderId: req.user._id, senderName: req.user.parentName || req.user.username, content, groupId, timestamp: new Date(), isRead: false });
        await announcement.save();

        res.status(200).json({ message: 'Date marked as non-operational.' });
    } catch (error) {
        console.error('Error marking non-operational date:', error);
        res.status(500).json({ message: 'Error marking date.' });
    }
});

/**
 * POST /api/calendar/nonop/bulk
 * Body: { startDate: 'YYYY-MM-DD', endDate: 'YYYY-MM-DD', occasion: '...' }
 * Marks all Sundays in the span as non-operational. Creates a single announcement describing the span.
 */
app.post('/api/calendar/nonop/bulk', authenticateToken, authorize(['admin', 'secretary']), async (req, res) => {
    try {
        const { startDate, endDate, occasion } = req.body;
        if (!startDate || !endDate) return res.status(400).json({ message: 'Start and end dates are required.' });

        const start = new Date(startDate);
        start.setHours(0,0,0,0);
        const end = new Date(endDate);
        end.setHours(0,0,0,0);
        if (end < start) return res.status(400).json({ message: 'End date must be after start date.' });

        // Find all Sundays in the span
        const datesToCreate = [];
        for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
            if (d.getDay() === 0) { // Sunday
                datesToCreate.push(new Date(d.getFullYear(), d.getMonth(), d.getDate()));
            }
        }

        const groupId = crypto.randomBytes(8).toString('hex');
        const ops = [];
        for (const dt of datesToCreate) {
            // upsert: avoid duplicates
            ops.push({ updateOne: { filter: { date: dt }, update: { $set: { date: dt, occasion: occasion || '', groupId, createdBy: req.user._id } }, upsert: true } });
        }

        if (ops.length > 0) {
            await NonOperation.bulkWrite(ops);
        }

        // Single announcement for the span (include groupId token)
        const fmtStart = start.toLocaleDateString();
        const fmtEnd = end.toLocaleDateString();
    const content = `Service Suspension: Bus will NOT run from ${fmtStart} through ${fmtEnd}` + (occasion ? ` — ${occasion}` : '');
    const announcement = new Message({ conversationId: 'global', senderId: req.user._id, senderName: req.user.parentName || req.user.username, content, groupId, timestamp: new Date(), isRead: false });
        await announcement.save();

        res.status(200).json({ message: `Marked ${datesToCreate.length} Sundays as non-operational.` });
    } catch (error) {
        console.error('Error creating bulk non-operational dates:', error);
        res.status(500).json({ message: 'Error marking bulk dates.' });
    }
});

/**
 * DELETE /api/calendar/nonop/:id
 * Removes a non-operation entry (re-opens service on that Sunday) and announces the change.
 */
app.delete('/api/calendar/nonop/:id', authenticateToken, authorize(['admin', 'secretary']), async (req, res) => {
    try {
        const { id } = req.params;
        const doc = await NonOperation.findByIdAndDelete(id);
        if (!doc) return res.status(404).json({ message: 'Non-operation date not found.' });

        // Remove any scheduled/global announcements tied to this groupId (if present)
        if (doc.groupId) {
            try {
                await Message.deleteMany({ conversationId: 'global', groupId: doc.groupId });
            } catch (delErr) {
                console.error('Error deleting related announcements by groupId:', delErr);
            }
        } else {
            // Fallback: remove messages containing the date string
            try {
                const dateToken = new Date(doc.date).toLocaleDateString();
                await Message.deleteMany({ conversationId: 'global', content: new RegExp(dateToken) });
            } catch (delErr) {
                console.error('Error deleting date-related announcements:', delErr);
            }
        }

        const content = `Service Update: Bus WILL run on ${new Date(doc.date).toLocaleDateString()} (previously marked non-operational).`;
        const announcement = new Message({ conversationId: 'global', senderId: req.user._id, senderName: req.user.parentName || req.user.username, content, timestamp: new Date(), isRead: false });
        await announcement.save();

        res.status(200).json({ message: 'Non-operation date removed.' });
    } catch (error) {
        console.error('Error deleting non-operation date:', error);
        res.status(500).json({ message: 'Error removing date.' });
    }
});


/**
 * GET /api/notifications
 * Fetches recent, unread notifications.
 */
app.get('/api/notifications', authenticateToken, authorize(['admin', 'secretary', 'driver']), async (req, res) => {
    try {
        // Fetch all unread notifications from the last 14 days, newest first.
        const twoWeeksAgo = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000);
        const notifications = await Notification.find({
            createdAt: { $gte: twoWeeksAgo },
            isRead: false // Only fetch unread notifications
        }).sort({ createdAt: -1 });

        res.status(200).json(notifications);
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).send('Internal server error.');
    }
});

/**
 * POST /api/notifications/mark-read
 * Marks notifications as read, excluding temporary changes for the current Sunday.
 */
app.post('/api/notifications/mark-read', authenticateToken, authorize(['admin', 'secretary', 'driver']), async (req, res) => {
    try {
        // Mark all notifications as read. No exclusions.
        const result = await Notification.updateMany(
            { isRead: false }, // Target only unread notifications
            { $set: { isRead: true } }
        );

        res.status(200).json({ message: 'Notifications cleared.', modifiedCount: result.modifiedCount });
    } catch (error) {
        console.error('Error marking notifications as read:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// -----------------------------------------------------
// 4. MESSAGING ROUTES
// -----------------------------------------------------

/**
 * POST /api/messages
 * Handles sending a message (from rider or secretary)
 */
app.post('/api/messages', authenticateToken, async (req, res) => { // Added authenticateToken middleware
    try {
        const { conversationId, senderId, senderName, content } = req.body;
        if (!conversationId || !senderId || !senderName || !content) {
            return res.status(400).json({ message: 'Missing required message fields.' });
        }

        // A message is considered "read" by default if it's sent by a secretary or admin.
        // It's "unread" (isRead: false) if sent by a rider.
        const isSenderStaff = ['secretary', 'admin'].includes(req.user.role);

        const newMessage = new Message({
            conversationId,
            senderId: new mongoose.Types.ObjectId(senderId), // Correctly cast senderId to ObjectId
            senderName,
            content,
            isRead: isSenderStaff // Set isRead based on sender's role
        });

        await newMessage.save();
        res.status(201).json(newMessage);

    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ message: 'Error sending message.' });
    }
});

/**
 * GET /api/messages/:conversationId
 * Fetches all messages for a specific conversation (a rider's chat or global)
 */
app.get('/api/messages/:conversationId', authenticateToken, async (req, res) => {
    try {
        const { conversationId } = req.params;
        const messages = await Message.find({ conversationId }).sort({ timestamp: 1 }); // Sort oldest to newest
        res.status(200).json(messages);
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ message: 'Error fetching messages.' });
    }
});

/**
 * POST /api/messages/global/clear
 * Deletes all global announcements.
 */
app.post('/api/messages/global/clear', authenticateToken, authorize(['admin', 'secretary']), async (req, res) => {
    try {
        const result = await Message.deleteMany({ conversationId: 'global' });

        if (result.deletedCount === 0) {
            return res.status(200).json({ message: 'No announcements to clear.' });
        }

        res.status(200).json({ message: `${result.deletedCount} announcements cleared successfully.` });
    } catch (error) {
        console.error('Error clearing global announcements:', error);
        res.status(500).json({ message: 'Error clearing announcements.' });
    }
});

/**
 * POST /api/messages/mark-as-read
 * Marks all messages in a conversation as read.
 */
app.post('/api/messages/mark-as-read', authenticateToken, authorize(['admin', 'secretary']), async (req, res) => {
    const { conversationId } = req.body;
    if (!conversationId) {
        return res.status(400).json({ message: 'Conversation ID is required.' });
    }

    try {
        // Mark messages sent by others in this conversation as read
        await Message.updateMany({ conversationId, senderId: { $ne: new mongoose.Types.ObjectId(req.user._id) }, isRead: false }, { $set: { isRead: true } }); // Explicitly cast req.user._id to ObjectId
        res.status(200).json({ message: 'Messages marked as read.' });
    } catch (error) {
        console.error('Error marking messages as read:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

/**
 * DELETE /api/messages/:id
 * Deletes a specific message by its ID. Used for removing broadcasts.
 */
app.delete('/api/messages/:id', authenticateToken, authorize(['admin', 'secretary']), async (req, res) => {
    try {
        const { id } = req.params;
        const result = await Message.findByIdAndDelete(id);

        if (!result) {
            return res.status(404).json({ message: 'Message not found.' });
        }

        res.status(200).json({ message: 'Message deleted successfully.' });

    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ message: 'Error deleting message.' });
    }
});


// -----------------------------------------------------
// 5. SERVER START
// -----------------------------------------------------

app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});

// -----------------------------------------------------
// Scheduler: create global announcements starting two months before non-op dates
// Runs at startup and once every 24 hours
// -----------------------------------------------------
async function createAdvanceAnnouncements() {
    try {
        const now = new Date();
        const twoMonthsMs = 60 * 24 * 60 * 60 * 1000; // 60 days
        const windowEnd = new Date(Date.now() + twoMonthsMs);

        // Fetch NonOperation entries whose date is between today and two months from now
        const upcoming = await NonOperation.find({ date: { $gte: now, $lte: windowEnd } });

        for (const n of upcoming) {
            const gid = n.groupId || '';
            // Check if an announcement already exists for this groupId
            let exists = false;
            if (gid) {
                exists = await Message.exists({ conversationId: 'global', content: new RegExp(`\\[gid:${gid}\\]`) });
            }
            if (!exists) {
                // Double-check by date fallback (in case groupId missing)
                if (!gid) {
                    const dateToken = new Date(n.date).toLocaleDateString();
                    exists = await Message.exists({ conversationId: 'global', content: new RegExp(dateToken) });
                }
            }

            if (!exists) {
                const fmt = new Date(n.date).toLocaleDateString();
                const content = `Service Suspension: Bus will NOT run on ${fmt}` + (n.occasion ? ` — ${n.occasion}` : '');
                const announcement = new Message({ conversationId: 'global', senderId: null, senderName: 'System', content, groupId: gid || undefined, timestamp: new Date(), isRead: false });
                await announcement.save();
                console.log('Scheduled announcement created for non-op date:', fmt, gid || 'no-gid');
            }
        }

    } catch (err) {
        console.error('Error creating advance announcements:', err);
    }
}

// Run once immediately, then every 24 hours
createAdvanceAnnouncements();
setInterval(createAdvanceAnnouncements, 24 * 60 * 60 * 1000);