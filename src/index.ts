import express, { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import 'dotenv/config';
import { databaseHost, databaseName, databasePassword, databasePort, databaseUser } from './config';
const app = express();
const PORT = 3000;
import cors from 'cors';
import cookieParser from 'cookie-parser';
const JWT_SECRET = 'your-secret-key'; // In production, use environment variable

// Extended Request interface to include user property
interface AuthenticatedRequest extends Request {
	user?: {
		id: number;
		email: string;
		name: string;
	};
}

// Define JWT payload type
interface JwtPayload {
	id: number;
	email: string;
	name: string;
}

const corsOptions = {
	origin: ['http://localhost:5173', 'http://localhost:5174'],
	credentials: true,
	optionSuccessStatus: 200,
};

// Multer configuration for image upload
const storage = multer.diskStorage({
	destination: './uploads/',
	filename: (req, file, cb) => {
		cb(null, Date.now() + path.extname(file.originalname));
	},
});

const upload = multer({ storage: storage });

// MySQL connection pool
const pool = mysql.createPool({
	host: databaseHost,
	user: databaseUser,
	password: databasePassword,
	port: databasePort,
	database: databaseName,
	waitForConnections: true,
	connectionLimit: 10,
	queueLimit: 0,
});

// Create tables if they don't exist
async function initDb() {
	const connection = await pool.getConnection();
	try {
		await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

		await connection.query(`
      CREATE TABLE IF NOT EXISTS books (
        id INT AUTO_INCREMENT PRIMARY KEY,
        book_name VARCHAR(255) NOT NULL,
        author VARCHAR(255) NOT NULL,
        published_date DATE NOT NULL,
        posted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        image_path VARCHAR(255),
        rented BOOLEAN DEFAULT FALSE,
        user_id INT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
		await connection.query(`
		CREATE TABLE IF NOT EXISTS rentals (
		  id INT AUTO_INCREMENT PRIMARY KEY,
		  book_id INT NOT NULL,
		  user_id INT NOT NULL,
		  rental_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		  return_date TIMESTAMP NULL,
		  FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE,
		  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	  `);
	} finally {
		connection.release();
	}
}

initDb().catch(console.error);

// Middleware
app.use(express.json());
app.use(cors(corsOptions));
app.use('/uploads', express.static('uploads'));
app.use(cookieParser());

// Authentication middleware
const authenticateToken = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token) {
		res.status(401).json({ error: 'Authentication required' });
		return;
	}

	jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
		if (err) {
			res.status(403).json({ error: 'Invalid token' });
			return;
		}

		req.user = decoded as JwtPayload;
		next();
	});
};

// Register endpoint
app.post('/register', async (req: Request, res: Response): Promise<void> => {
	const { name, email, password } = req.body;

	if (!name || !email || !password) {
		res.status(400).json({ error: 'All fields are required' });
		return;
	}

	try {
		const hashedPassword = await bcrypt.hash(password, 10);
		await pool.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [
			name,
			email,
			hashedPassword,
		]);
		res.status(201).json({ message: 'User registered successfully' });
	} catch (error: any) {
		if (error.code === 'ER_DUP_ENTRY') {
			res.status(400).json({ error: 'Email already exists' });
			return;
		}
		res.status(500).json({ error: 'Error registering user' });
	}
});

// Login endpoint
app.post('/login', async (req: Request, res: Response): Promise<void> => {
	const { email, password } = req.body;

	try {
		const [rows]: any = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

		if (rows.length === 0) {
			res.status(400).json({ error: 'User not found' });
			return;
		}

		const user = rows[0];
		const validPassword = await bcrypt.compare(password, user.password);

		if (!validPassword) {
			res.status(400).json({ error: 'Invalid password' });
			return;
		}

		const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, {
			expiresIn: '24h',
		});

		res.json({ token, user });
	} catch (error) {
		res.status(500).json({ error: 'Error logging in' });
	}
});

// Post book endpoint
app.post(
	'/post-book',
	authenticateToken,
	upload.single('image'),
	async (req: AuthenticatedRequest, res: Response): Promise<void> => {
		const { book_name, author, published_date } = req.body;
		const userId = req.user?.id; // Get user ID from req.user instead of req.body.user
		if (!userId) {
			res.status(401).json({ error: 'User ID not found' });
			return;
		}

		const imagePath = req.file
			? `${process.env.SERVER_URL}/uploads/${req.file.filename}`
			: null;

		try {
			await pool.query(
				'INSERT INTO books (book_name, author, published_date, image_path, user_id) VALUES (?, ?, ?, ?, ?)',
				[book_name, author, published_date, imagePath, userId]
			);
			res.status(201).json({ message: 'Book posted successfully' });
		} catch (error) {
			console.error('Error posting book:', error);
			res.status(500).json({ error: 'Error posting book' });
		}
	}
);

// Update book endpoint
app.patch(
	'/update-book/:id',
	authenticateToken,
	upload.single('image'),
	async (req: AuthenticatedRequest, res: Response): Promise<void> => {
		const bookId = req.params.id;
		const userId = req.user?.id;
		const { book_name, author, published_date } = req.body;
		const imagePath = req.file ? `/uploads/${req.file.filename}` : undefined;

		try {
			// Check if the book belongs to the user
			const [rows]: any = await pool.query(
				'SELECT * FROM books WHERE id = ? AND user_id = ?',
				[bookId, userId]
			);

			if (rows.length === 0) {
				res.status(403).json({ error: 'Unauthorized to update this book' });
				return;
			}

			const updateFields = [];
			const updateValues = [];

			if (book_name) {
				updateFields.push('book_name = ?');
				updateValues.push(book_name);
			}
			if (author) {
				updateFields.push('author = ?');
				updateValues.push(author);
			}
			if (published_date) {
				updateFields.push('published_date = ?');
				updateValues.push(published_date);
			}
			if (imagePath) {
				updateFields.push('image_path = ?');
				updateValues.push(imagePath);
			}

			if (updateFields.length === 0) {
				res.status(400).json({ error: 'No fields to update' });
				return;
			}

			updateValues.push(bookId, userId);

			await pool.query(
				`UPDATE books SET ${updateFields.join(', ')} WHERE id = ? AND user_id = ?`,
				updateValues
			);

			res.json({ message: 'Book updated successfully' });
		} catch (error) {
			res.status(500).json({ error: 'Error updating book' });
		}
	}
);

// Delete book endpoint
app.delete(
	'/delete-book/:id',
	authenticateToken,
	async (req: AuthenticatedRequest, res: Response): Promise<void> => {
		const bookId = req.params.id;
		const userId = req.user?.id;

		try {
			const [result]: any = await pool.query(
				'DELETE FROM books WHERE id = ? AND user_id = ?',
				[bookId, userId]
			);

			if (result.affectedRows === 0) {
				res.status(403).json({
					error: 'Unauthorized to delete this book or book not found',
				});
				return;
			}

			res.json({ message: 'Book deleted successfully' });
		} catch (error) {
			res.status(500).json({ error: 'Error deleting book' });
		}
	}
);

// Get all books endpoint
app.get('/books', async (req: Request, res: Response) => {
	try {
		const [rows] = await pool.query(`
      SELECT b.id, b.image_path, b.book_name, b.author, b.published_date, b.rented,
             u.name as user_name
      FROM books b
      JOIN users u ON b.user_id = u.id
      ORDER BY b.posted_date DESC
    `);
		res.json(rows);
	} catch (error) {
		res.status(500).json({ error: 'Error fetching books' });
	}
});

// Get single book endpoint
app.get('/books/:id', async (req: Request, res: Response): Promise<void> => {
	const bookId = req.params.id;

	try {
		const [rows]: any = await pool.query(
			`
            SELECT b.id, b.image_path, b.book_name, b.author, b.published_date, b.rented,
                   u.name as user_name, u.id as user_id
            FROM books b
            JOIN users u ON b.user_id = u.id
            WHERE b.id = ?
        `,
			[bookId]
		);

		if (rows.length === 0) {
			res.status(404).json({ error: 'Book not found' });
			return;
		}

		res.json(rows[0]);
	} catch (error) {
		console.error('Error fetching book:', error);
		res.status(500).json({ error: 'Error fetching book details' });
	}
});

// Rent book endpoint
app.post(
	'/rent-book/:id',
	authenticateToken,
	async (req: AuthenticatedRequest, res: Response): Promise<void> => {
		const bookId = req.params.id;
		const userId = req.user?.id;

		const connection = await pool.getConnection();

		try {
			await connection.beginTransaction();

			// Check if the book is available and not owned by the requesting user
			const [bookRows]: any = await connection.query(
				'SELECT user_id, rented FROM books WHERE id = ?',
				[bookId]
			);

			if (bookRows.length === 0) {
				await connection.rollback();
				res.status(404).json({ error: 'Book not found' });
				return;
			}

			const book = bookRows[0];

			if (book.user_id === userId) {
				await connection.rollback();
				res.status(400).json({ error: 'You cannot rent your own book' });
				return;
			}

			if (book.rented) {
				await connection.rollback();
				res.status(400).json({ error: 'Book is already rented' });
				return;
			}

			// Create rental record
			await connection.query('INSERT INTO rentals (book_id, user_id) VALUES (?, ?)', [
				bookId,
				userId,
			]);

			// Update book status to rented
			await connection.query('UPDATE books SET rented = TRUE WHERE id = ?', [bookId]);

			await connection.commit();
			res.json({ message: 'Book rented successfully' });
		} catch (error) {
			await connection.rollback();
			console.error('Error renting book:', error);
			res.status(500).json({ error: 'Error renting book' });
		} finally {
			connection.release();
		}
	}
);

// Optional: Add endpoint to return a book
app.post(
	'/return-book/:id',
	authenticateToken,
	async (req: AuthenticatedRequest, res: Response): Promise<void> => {
		const bookId = req.params.id;
		const userId = req.user?.id;

		const connection = await pool.getConnection();

		try {
			await connection.beginTransaction();

			// Check if the user has rented this book
			const [rentalRows]: any = await connection.query(
				'SELECT id FROM rentals WHERE book_id = ? AND user_id = ? AND return_date IS NULL',
				[bookId, userId]
			);

			if (rentalRows.length === 0) {
				await connection.rollback();
				res.status(400).json({ error: 'No active rental found for this book' });
				return;
			}

			// Update rental record
			await connection.query(
				'UPDATE rentals SET return_date = CURRENT_TIMESTAMP WHERE id = ?',
				[rentalRows[0].id]
			);

			// Update book status
			await connection.query('UPDATE books SET rented = FALSE WHERE id = ?', [bookId]);

			await connection.commit();
			res.json({ message: 'Book returned successfully' });
		} catch (error) {
			await connection.rollback();
			console.error('Error returning book:', error);
			res.status(500).json({ error: 'Error returning book' });
		} finally {
			connection.release();
		}
	}
);

// Start server
app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});
