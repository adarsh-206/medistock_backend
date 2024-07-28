import express from 'express';
import dotenv from 'dotenv';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import cors from 'cors';
import connectDB from './config/connectDB.js';
import authRoutes from './routes/authRoutes.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

connectDB();

app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(cors());

app.use('/api/auth', authRoutes);

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});