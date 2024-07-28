import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { validationResult } from 'express-validator';
import User from '../models/user.js';
import OTP from '../models/OTP.js';
import transporter from '../config/nodeMailer.js';
import dotenv from 'dotenv';

dotenv.config();

export const register = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, email, password, mobile } = req.body;

  try {
    let user = await User.findOne({ email });

    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate 6-digit OTP
    const newOtp = new OTP({ email, otp, expiresAt: Date.now() + 600000 }); // Set expiration time to 10 minutes from now

    user = new User({ name, email, password, mobile });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    await user.save();
    await newOtp.save();

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP code is ${otp}. It will expire in 5 minutes.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ message: 'Error sending OTP', error });
      }
      res.status(201).json({ message: 'User registered. Please check your email for the OTP.' });
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
};

export const verifyOtp = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, otp } = req.body;

  try {
    const otpRecord = await OTP.findOne({ email, otp });

    if (!otpRecord) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (otpRecord.expiresAt < Date.now()) {
      return res.status(400).json({ message: 'OTP has expired' });
    }

    await OTP.deleteOne({ email, otp }); // Remove OTP after successful verification

    const user = await User.findOne({ email });

    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      if (err) throw err;
      res.json({ token, message: 'OTP verified successfully' });
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
};


export const login = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      if (err) throw err;
      res.json({ token });
    });
  } catch (error) {
    console.error(error.message);
    res.status(500).send('Server error');
  }
};

export default { register, login, sendOtp };