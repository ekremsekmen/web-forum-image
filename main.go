package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	os.MkdirAll("./uploads", os.ModePerm)
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = createTables(db)
	if err != nil {
		log.Fatalf("Tablolar oluşturulamadı: %v", err)
	}

	log.Println("Database Tables Created Successfully!")

	http.HandleFunc("/", logInPageHandler(db))
	http.HandleFunc("/register", registerPageHandler(db))
	http.HandleFunc("/guestLogin", guestLoginHandler())
	http.HandleFunc("/forum", forumPageHandler(db))
	http.HandleFunc("/createPost", authorize(createPostHandler(db)))
	http.HandleFunc("/like", authorize(likeHandler(db)))
	http.HandleFunc("/dislike", authorize(dislikeHandler(db)))
	http.HandleFunc("/comment", authorize(commentHandler(db)))

	// Serve static files from the ./uploads directory
	http.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("./uploads"))))

	log.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}

func createTables(db *sql.DB) error {
	createUsersTable := `
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );`

	createPostsTable := `
    CREATE TABLE IF NOT EXISTS Posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        image_url TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        likes INTEGER DEFAULT 0,
        dislikes INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES Users(id)
    );`

	createCommentsTable := `
    CREATE TABLE IF NOT EXISTS Comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES Users(id),
        FOREIGN KEY (post_id) REFERENCES Posts(id)
    );`

	createLikesTable := `
    CREATE TABLE IF NOT EXISTS Likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        UNIQUE (user_id, post_id),
        FOREIGN KEY (user_id) REFERENCES Users(id),
        FOREIGN KEY (post_id) REFERENCES Posts(id)
    );`

	createDislikesTable := `
    CREATE TABLE IF NOT EXISTS Dislikes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        UNIQUE (user_id, post_id),
        FOREIGN KEY (user_id) REFERENCES Users(id),
        FOREIGN KEY (post_id) REFERENCES Posts(id)
    );`

	_, err := db.Exec(createUsersTable)
	if err != nil {
		return err
	}

	_, err = db.Exec(createPostsTable)
	if err != nil {
		return err
	}

	_, err = db.Exec(createCommentsTable)
	if err != nil {
		return err
	}

	_, err = db.Exec(createLikesTable)
	if err != nil {
		return err
	}

	_, err = db.Exec(createDislikesTable)
	if err != nil {
		return err
	}

	return nil
}

func registerUser(db *sql.DB, email, username, password string) error {
	query := "INSERT INTO Users (email, username, password) VALUES (?, ?, ?)"
	_, err := db.Exec(query, email, username, password)
	return err
}

func registerPageHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tmpl := template.Must(template.ParseFiles("register.html"))
			tmpl.Execute(w, nil)
			return
		}

		if r.Method == http.MethodPost {
			email := r.FormValue("email")
			username := r.FormValue("username")
			password := r.FormValue("password")

			err := registerUser(db, email, username, password)
			if err != nil {
				http.Error(w, "Unable to register user", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}
}

func logInPageHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tmpl := template.Must(template.ParseFiles("login.html"))
			tmpl.Execute(w, nil)
			return
		}

		if r.Method == http.MethodPost {
			email := r.FormValue("email")
			password := r.FormValue("password")

			valid, userID, err := authenticateUser(db, email, password)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if valid {
				setSession(w, "user", email)
				setSession(w, "userID", strconv.Itoa(userID))
				http.Redirect(w, r, "/forum", http.StatusSeeOther)
			} else {
				http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
			}
		}
	}
}

func authenticateUser(db *sql.DB, email, password string) (bool, int, error) {
	var dbEmail, dbPassword string
	var userID int
	err := db.QueryRow("SELECT id, email, password FROM Users WHERE email = ?", email).Scan(&userID, &dbEmail, &dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, 0, fmt.Errorf("user not found")
		}
		return false, 0, err
	}

	if password == dbPassword {
		return true, userID, nil
	}
	return false, 0, fmt.Errorf("invalid password")
}

type Post struct {
	ID        int
	Title     string
	Content   string
	Username  string
	CreatedAt string
	Likes     int
	Dislikes  int
	ImageURL  string
	Comments  []Comment
}

type Comment struct {
	Content   string
	Username  string
	CreatedAt string
}

func forumPageHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			posts, err := fetchPosts(db)
			if err != nil {
				http.Error(w, "Unable to load posts", http.StatusInternalServerError)
				return
			}

			tmpl := template.Must(template.ParseFiles("index.html"))
			tmpl.Execute(w, struct{ Posts []Post }{Posts: posts})
		}
	}
}

func fetchPosts(db *sql.DB) ([]Post, error) {
	rows, err := db.Query(`
        SELECT Posts.id, Posts.title, Posts.content, Users.username, Posts.created_at, Posts.image_url,
               (SELECT COUNT(*) FROM Likes WHERE Likes.post_id = Posts.id) as likes,
               (SELECT COUNT(*) FROM Dislikes WHERE Dislikes.post_id = Posts.id) as dislikes
        FROM Posts
        JOIN Users ON Posts.user_id = Users.id
        ORDER BY Posts.created_at DESC
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Username, &post.CreatedAt, &post.ImageURL, &post.Likes, &post.Dislikes); err != nil {
			return nil, err
		}

		comments, err := fetchComments(db, post.ID)
		if err != nil {
			return nil, err
		}
		post.Comments = comments

		posts = append(posts, post)
	}
	return posts, nil
}

func fetchComments(db *sql.DB, postID int) ([]Comment, error) {
	rows, err := db.Query(`
        SELECT Comments.content, Users.username, Comments.created_at
        FROM Comments
        JOIN Users ON Comments.user_id = Users.id
        WHERE Comments.post_id = ?
        ORDER BY Comments.created_at ASC
    `, postID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		if err := rows.Scan(&comment.Content, &comment.Username, &comment.CreatedAt); err != nil {
			return nil, err
		}
		comments = append(comments, comment)
	}
	return comments, nil
}

func createPostHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			title := r.FormValue("title")
			content := r.FormValue("content")
			userID, err := strconv.Atoi(getSession(r, "userID"))
			if err != nil {
				http.Error(w, "Unable to get user ID", http.StatusInternalServerError)
				return
			}

			// Resim dosyasını al
			file, header, err := r.FormFile("image")
			if err != nil && err != http.ErrMissingFile {
				http.Error(w, "Unable to get uploaded file", http.StatusInternalServerError)
				return
			}
			defer file.Close()

			var imageURL string
			if header != nil {
				// Resmi kaydet
				imageURL, err = saveImage(file, header)
				if err != nil {
					http.Error(w, "Unable to save image", http.StatusInternalServerError)
					return
				}
			}

			err = createPost(db, title, content, imageURL, userID)
			if err != nil {
				http.Error(w, "Unable to create post", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/forum", http.StatusSeeOther)
		}
	}
}

func saveImage(file multipart.File, header *multipart.FileHeader) (string, error) {
	// Dosya boyutunu kontrol et (maksimum 20 MB)
	const maxFileSize = 15 << 20 // 20 MB
	if header.Size > maxFileSize {
		return "", fmt.Errorf("dosya boyutu çok büyük (maksimum 20 MB)")
	}

	// Dosyanın içeriğini oku ve ilk 512 byte'ı al
	buffer := make([]byte, 512)
	_, err := file.Read(buffer)
	if err != nil {
		return "", err
	}

	// Dosya türünü belirle
	filetype := http.DetectContentType(buffer)
	switch filetype {
	case "image/jpeg", "image/jpg", "image/png", "image/gif":
		// Geçerli dosya türleri
	default:
		return "", fmt.Errorf("sadece JPG, JPEG, PNG ve GIF dosyaları yüklenebilir")
	}

	// Dosya uzantısını kontrol et
	ext := filepath.Ext(header.Filename)
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif":
		// Geçerli dosya uzantıları
	default:
		return "", fmt.Errorf("sadece JPG, JPEG, PNG ve GIF dosyaları yüklenebilir")
	}

	// Dosya adını oluştur
	imagePath := filepath.Join("./uploads", header.Filename)
	out, err := os.Create(imagePath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	// Dosyanın içeriğini tekrar oku ve tamamını yaz
	file.Seek(0, 0) // Dosyanın başına dön
	_, err = io.Copy(out, file)
	if err != nil {
		return "", err
	}

	// Geriye dosya adını döndür (yol değil)
	return header.Filename, nil
}

func createPost(db *sql.DB, title, content, imageURL string, userID int) error {
	query := "INSERT INTO Posts (title, content, user_id, image_url) VALUES (?, ?, ?, ?)"
	_, err := db.Exec(query, title, content, userID, imageURL)
	return err
}

func likeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postID := r.FormValue("post_id")
			userID, err := strconv.Atoi(getSession(r, "userID"))
			if err != nil {
				http.Error(w, "Unable to get user ID", http.StatusInternalServerError)
				return
			}

			err = likePost(db, postID, userID)
			if err != nil {
				http.Error(w, "Unable to like post", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/forum", http.StatusSeeOther)
		}
	}
}

func likePost(db *sql.DB, postID string, userID int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existingID int
	err = tx.QueryRow("SELECT id FROM Likes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if existingID == 0 {
		_, err = tx.Exec("INSERT INTO Likes (post_id, user_id) VALUES (?, ?)", postID, userID)
		if err != nil {
			return err
		}

		_, err = tx.Exec("UPDATE Posts SET likes = likes + 1 WHERE id = ?", postID)
		if err != nil {
			return err
		}

		_, err = tx.Exec("DELETE FROM Dislikes WHERE post_id = ? AND user_id = ?", postID, userID)
		if err != nil {
			return err
		}

		_, err = tx.Exec("UPDATE Posts SET dislikes = dislikes - 1 WHERE id = ? AND (SELECT COUNT(*) FROM Dislikes WHERE post_id = ? AND user_id = ?) > 0", postID, postID, userID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func dislikeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postID := r.FormValue("post_id")
			userID, err := strconv.Atoi(getSession(r, "userID"))
			if err != nil {
				http.Error(w, "Unable to get user ID", http.StatusInternalServerError)
				return
			}

			err = dislikePost(db, postID, userID)
			if err != nil {
				http.Error(w, "Unable to dislike post", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/forum", http.StatusSeeOther)
		}
	}
}

func dislikePost(db *sql.DB, postID string, userID int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existingID int
	err = tx.QueryRow("SELECT id FROM Dislikes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if existingID == 0 {
		_, err = tx.Exec("INSERT INTO Dislikes (post_id, user_id) VALUES (?, ?)", postID, userID)
		if err != nil {
			return err
		}

		_, err = tx.Exec("UPDATE Posts SET dislikes = dislikes + 1 WHERE id = ?", postID)
		if err != nil {
			return err
		}

		_, err = tx.Exec("DELETE FROM Likes WHERE post_id = ? AND user_id = ?", postID, userID)
		if err != nil {
			return err
		}

		_, err = tx.Exec("UPDATE Posts SET likes = likes - 1 WHERE id = ? AND (SELECT COUNT(*) FROM Likes WHERE post_id = ? AND user_id = ?) > 0", postID, postID, userID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func commentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			content := r.FormValue("content")
			postID := r.FormValue("post_id")
			userID, err := strconv.Atoi(getSession(r, "userID"))
			if err != nil {
				http.Error(w, "Unable to get user ID", http.StatusInternalServerError)
				return
			}

			err = addComment(db, content, postID, userID)
			if err != nil {
				http.Error(w, "Unable to add comment", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/forum", http.StatusSeeOther)
		}
	}
}

func addComment(db *sql.DB, content, postID string, userID int) error {
	query := "INSERT INTO Comments (content, post_id, user_id) VALUES (?, ?, ?)"
	_, err := db.Exec(query, content, postID, userID)
	return err
}

func setSession(w http.ResponseWriter, key, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:  key,
		Value: value,
		Path:  "/",
	})
}

func getSession(r *http.Request, key string) string {
	cookie, err := r.Cookie(key)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func guestLoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSession(w, "user", "guest")
		setSession(w, "userID", "0")
		http.Redirect(w, r, "/forum", http.StatusSeeOther)
	}
}

func authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := getSession(r, "user")
		if user == "" || user == "guest" {
			http.Error(w, "Guest Users Cannot Do This Action", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}
