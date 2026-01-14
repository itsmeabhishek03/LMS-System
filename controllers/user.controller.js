import { User } from "../models/user.model.js";
import bcrypt from "bcryptjs";
import { generateToken } from "../utils/generateToken.js";
import { deleteMediaFromCloudinary, uploadMedia } from "../utils/cloudinary.js";
import { catchAsync } from "../middleware/error.middleware.js";
import { AppError } from "../middleware/error.middleware.js";
import crypto from "crypto";

/**
 * Create a new user account
 * @route POST /api/v1/users/signup
 */
export const createUserAccount = catchAsync(async (req, res) => {
  // TODO: Implement create user account functionality
  const { name, email, password, role='student' } = req.body;
   
  if(!name || !email || !password) {
    throw new AppError("Name, email and password are required", 400);
  }
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new AppError("User with this email already exists", 400);
  }
  
  const user = await User.create({
    name,
    email,
    password,
    role
  });

  await user.updateLastActive();
  generateToken(res, user, "User created successfully");
});

/**
 * Authenticate user and get token
 * @route POST /api/v1/users/signin
 */
export const authenticateUser = catchAsync(async (req, res) => {
  // TODO: Implement user authentication functionality
  const { email, password } = req.body;
  
  if (!email || !password) {
    throw new AppError("Email and password are required", 400);
  }

  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.comparePassword(password))) {
    throw new AppError("Invalid email or password", 401);
  }

  await user.updateLastActive();
  generateToken(res, user, "User authenticated successfully");
});

/**
 * Sign out user and clear cookie
 * @route POST /api/v1/users/signout
 */
export const signOutUser = catchAsync(async (_, res) => {
  // TODO: Implement sign out functionality
  res.cookie("token", "", {
    httpOnly: true,
    expires: new Date(0),
  });

  res.status(200).json({
    success: true,
    message: "User signed out successfully",
  });
});

/**
 * Get current user profile
 * @route GET /api/v1/users/profile
 */
export const getCurrentUserProfile = catchAsync(async (req, res) => {
  // TODO: Implement get current user profile functionality
  const user = await User.findById(req.id);

  res.status(200).json({
    success: true,
    data: user,
  });
});

/**
 * Update user profile
 * @route PATCH /api/v1/users/profile
 */
export const updateUserProfile = catchAsync(async (req, res) => {
  // TODO: Implement update user profile functionality
  const user = await User.findById(req.id);

  const { name, email, avatar , bio } = req.body;
  if (name) user.name = name;
  if (email) user.email = email;
  if (bio) user.bio = bio;

  if (avatar) {
    // Delete existing avatar from Cloudinary if not default
    if (user.avatar && user.avatar !== "default-avatar.png") {
      await deleteMediaFromCloudinary(user.avatar);
    }
    // Upload new avatar to Cloudinary
    const uploadedAvatar = await uploadMedia(avatar, "avatars");
    user.avatar = uploadedAvatar.secure_url;
  }

  await user.save();

  res.status(200).json({
    success: true,
    data: user,
    message: "User profile updated successfully",
  });
});

/**
 * Change user password
 * @route PATCH /api/v1/users/password
 */
export const changeUserPassword = catchAsync(async (req, res) => {
  // TODO: Implement change user password functionality
  const { currentPassword, newPassword } = req.body;
  const user = await User.findById(req.id).select("+password");

  if (!user || !(await user.comparePassword(currentPassword))) {
    throw new AppError("Current password is incorrect", 401);
  }

  user.password = newPassword;
  await user.save();
  res.status(200).json({
    success: true,
    message: "Password changed successfully",
  });
});

/**
 * Request password reset
 * @route POST /api/v1/users/forgot-password
 */
export const forgotPassword = catchAsync(async (req, res) => {
  // TODO: Implement forgot password functionality
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    throw new AppError("There is no user with that email address", 404);
  }
  
  // Generate reset token
  const resetToken = user.getResetPasswordToken();
  await user.save({ validateBeforeSave: false });
  res.status(200).json({ message: "Reset link sent to email" });
});

/**
 * Reset password
 * @route POST /api/v1/users/reset-password/:token
 */
export const resetPassword = catchAsync(async (req, res) => {
  const { password } = req.body;

  if (!password) {
    throw new AppError("Please provide a new password", 400);
  }

  // 1. Hash the token from URL
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  // 2. Find user with valid token and not expired
  const user = await User.findOne({
    resetPasswordToken: hashedToken,
    resetPasswordExpire: { $gt: Date.now() }
  });

  if (!user) {
    throw new AppError("Token is invalid or has expired", 400);
  }

  // 3. Set new password
  user.password = password;

  // 4. Clear reset fields
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;

  // 5. Save user (triggers password hashing)
  await user.save();

  res.status(200).json({
    success: true,
    message: "Password has been reset successfully"
  });
});


/**
 * Delete user account
 * @route DELETE /api/v1/users/account
 */
export const deleteUserAccount = catchAsync(async (req, res) => {
  // TODO: Implement delete user account functionality
  await User.findByIdAndDelete(req.id);
  
  res.cookie("token", "", {
    httpOnly: true,
    expires: new Date(0),
  });
  res.status(200).json({
    success: true,
    message: "User account deleted successfully",
  });
});
