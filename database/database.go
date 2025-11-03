package database

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var (
	DB *pgxpool.Pool

	localPostgresOnce    sync.Once
	localPostgresErr     error
	localPostgresCmd     *exec.Cmd
	localPostgresStarted bool
	localPostgresLog     *os.File
	closeOnce            sync.Once
)

const (
	defaultAppDSN      = "postgres://user:password@/gogo?host=/tmp&port=5433&sslmode=disable"
	defaultAdminDSN    = "postgres://user@/postgres?host=/tmp&port=5433&sslmode=disable"
	localDataDirectory = "localpg"
	localLogFile       = "postgres.log"
)

func Connect() error {
	connStr := strings.TrimSpace(os.Getenv("DATABASE_URL"))

	candidates := []string{}
	if connStr != "" {
		candidates = append(candidates, connStr)
	} else {
		candidates = append(candidates, defaultAppDSN)
	}
	candidates = append(candidates, "postgres://user:password@localhost:5432/gogo?sslmode=disable")

	var lastErr error
	for idx, dsn := range candidates {
		for attempt := 0; attempt < 2; attempt++ {
			config, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				lastErr = fmt.Errorf("invalid database url %q: %w", dsn, err)
				break
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			pool, err := pgxpool.ConnectConfig(ctx, config)
			cancel()
			if err == nil {
				DB = pool
				return nil
			}

			lastErr = fmt.Errorf("connect failed for %q: %w", dsn, err)

			// If no explicit DATABASE_URL and this is the first candidate, try to provision local Postgres once.
			if connStr == "" && idx == 0 && attempt == 0 {
				if err := ensureLocalPostgres(); err != nil {
					lastErr = fmt.Errorf("failed to bootstrap local postgres: %w", err)
					break
				}
				time.Sleep(200 * time.Millisecond)
				continue
			}
			break
		}
	}

	if lastErr == nil {
		lastErr = errors.New("no database connection string provided")
	}
	return fmt.Errorf("Unable to connect to database: %v", lastErr)
}

// Close releases database connections and stops the local Postgres process if it was started automatically.
func Close() {
	closeOnce.Do(func() {
		if DB != nil {
			DB.Close()
		}
		stopLocalPostgres()
	})
}

func Migrate() error {
	_, err := DB.Exec(context.Background(), `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            first_name TEXT DEFAULT '',
            last_name TEXT DEFAULT '',
            avatar_url TEXT
        );

        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            price NUMERIC(10, 2) NOT NULL,
            image_url TEXT,
            size TEXT
        );

        CREATE TABLE IF NOT EXISTS banner_images (
            id SERIAL PRIMARY KEY,
            image_url TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        ALTER TABLE products
            ADD COLUMN IF NOT EXISTS size TEXT;

        CREATE TABLE IF NOT EXISTS favorites (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            PRIMARY KEY (user_id, product_id)
        );

        CREATE TABLE IF NOT EXISTS cart_items (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            size TEXT NOT NULL DEFAULT '',
            quantity INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            PRIMARY KEY (user_id, product_id, size)
        );

        CREATE TABLE IF NOT EXISTS user_addresses (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            address TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS user_saved_addresses (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            address TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            total NUMERIC(10, 2) NOT NULL,
            delivery_type TEXT DEFAULT 'pickup',
            pickup_point TEXT,
            address TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS order_items (
            id SERIAL PRIMARY KEY,
            order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
            product_id INTEGER NOT NULL REFERENCES products(id),
            product_name TEXT NOT NULL,
            product_price NUMERIC(10, 2) NOT NULL,
            size TEXT NOT NULL DEFAULT '',
            quantity INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS home_highlights (
            id SERIAL PRIMARY KEY,
            product_id INTEGER UNIQUE NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            position INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS menu_section_images (
            section TEXT PRIMARY KEY,
            image_url TEXT NOT NULL,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        ALTER TABLE users
            ADD COLUMN IF NOT EXISTS first_name TEXT DEFAULT '';

        ALTER TABLE users
            ADD COLUMN IF NOT EXISTS last_name TEXT DEFAULT '';

        ALTER TABLE users
            ADD COLUMN IF NOT EXISTS avatar_url TEXT;

        ALTER TABLE cart_items
            ADD COLUMN IF NOT EXISTS size TEXT NOT NULL DEFAULT '';

        ALTER TABLE cart_items
            DROP CONSTRAINT IF EXISTS cart_items_pkey;

        ALTER TABLE cart_items
            ADD CONSTRAINT cart_items_pkey PRIMARY KEY (user_id, product_id, size);
    `)
	return err
}

type User struct {
	ID           int
	Email        string
	PasswordHash string
	IsAdmin      bool
	FirstName    string
	LastName     string
	AvatarURL    string
}

type UserSavedAddress struct {
	ID        int
	UserID    int
	Address   string
	CreatedAt time.Time
}

type MenuSectionImage struct {
	Section   string
	ImageURL  string
	UpdatedAt time.Time
}

func CreateUserWithHash(email, passwordHash, firstName, lastName string, isAdmin bool) (*User, error) {
	user := &User{
		Email:        email,
		PasswordHash: passwordHash,
		IsAdmin:      isAdmin,
		FirstName:    strings.TrimSpace(firstName),
		LastName:     strings.TrimSpace(lastName),
	}

	err := DB.QueryRow(context.Background(),
		"INSERT INTO users (email, password_hash, is_admin, first_name, last_name, avatar_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		user.Email, user.PasswordHash, user.IsAdmin, user.FirstName, user.LastName, user.AvatarURL).Scan(&user.ID)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func CreateUser(email, password, firstName, lastName string, isAdmin bool) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return CreateUserWithHash(email, string(hashedPassword), firstName, lastName, isAdmin)
}

func UpdateUserPasswordHash(userID int, passwordHash string) error {
	_, err := DB.Exec(context.Background(),
		"UPDATE users SET password_hash = $1 WHERE id = $2",
		passwordHash, userID)
	return err
}

func ensureLocalPostgres() error {
	localPostgresOnce.Do(func() {
		localPostgresErr = launchLocalPostgres()
	})
	return localPostgresErr
}

func launchLocalPostgres() error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}

	dataDir := filepath.Join(workingDir, localDataDirectory)
	if err := initLocalDataDir(dataDir); err != nil {
		return err
	}

	logPath := filepath.Join(dataDir, localLogFile)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	cmd := exec.Command("postgres",
		"-D", dataDir,
		"-k", "/tmp",
		"-p", "5433",
		"-c", "listen_addresses=",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start postgres: %w", err)
	}

	localPostgresCmd = cmd
	localPostgresStarted = true
	localPostgresLog = logFile

	if err := waitForPostgresReady(defaultAdminDSN, 10*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = logFile.Close()
		localPostgresLog = nil
		return fmt.Errorf("postgres did not become ready: %w", err)
	}

	if err := bootstrapLocalPostgres(); err != nil {
		_ = cmd.Process.Kill()
		_ = logFile.Close()
		localPostgresLog = nil
		return fmt.Errorf("bootstrap local postgres: %w", err)
	}

	return nil
}

func initLocalDataDir(dataDir string) error {
	pgVersionPath := filepath.Join(dataDir, "PG_VERSION")
	if _, err := os.Stat(pgVersionPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat data dir: %w", err)
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	cmd := exec.Command("initdb", "-D", dataDir, "-U", "user", "-A", "trust")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("initdb failed: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}

	return nil
}

func waitForPostgresReady(dsn string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return errors.New("timeout waiting for postgres to become available")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		conn, err := pgx.Connect(ctx, dsn)
		cancel()
		if err == nil {
			conn.Close(context.Background())
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func bootstrapLocalPostgres() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, defaultAdminDSN)
	if err != nil {
		return fmt.Errorf("connect for bootstrap: %w", err)
	}
	defer conn.Close(context.Background())

	if _, err := conn.Exec(context.Background(), `ALTER USER "user" WITH PASSWORD 'password'`); err != nil {
		return fmt.Errorf("set user password: %w", err)
	}

	var exists bool
	if err := conn.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'gogo')`).Scan(&exists); err != nil {
		return fmt.Errorf("check database existence: %w", err)
	}

	if !exists {
		if _, err := conn.Exec(context.Background(), `CREATE DATABASE gogo`); err != nil {
			return fmt.Errorf("create database: %w", err)
		}
	}

	return nil
}

func stopLocalPostgres() {
	if !localPostgresStarted || localPostgresCmd == nil {
		return
	}

	waitCh := make(chan struct{})
	go func(cmd *exec.Cmd) {
		_ = cmd.Wait()
		close(waitCh)
	}(localPostgresCmd)

	_ = localPostgresCmd.Process.Signal(os.Interrupt)

	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
		_ = localPostgresCmd.Process.Kill()
	}
	localPostgresCmd = nil
	localPostgresStarted = false
	if localPostgresLog != nil {
		_ = localPostgresLog.Close()
		localPostgresLog = nil
	}
}

func GetUserByEmail(email string) (*User, error) {
	user := &User{}
	err := DB.QueryRow(context.Background(),
		"SELECT id, email, password_hash, is_admin, COALESCE(first_name, ''), COALESCE(last_name, ''), COALESCE(avatar_url, '') FROM users WHERE email = $1",
		email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.IsAdmin, &user.FirstName, &user.LastName, &user.AvatarURL)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func UpdateUserAvatar(userID int, avatarURL string) error {
	_, err := DB.Exec(context.Background(),
		"UPDATE users SET avatar_url = $1 WHERE id = $2",
		strings.TrimSpace(avatarURL), userID)
	return err
}

type Product struct {
	ID          int
	Name        string
	Description string
	Price       float64
	ImageURL    string
	Size        string
}

type BannerImage struct {
	ID       int
	ImageURL string
}

func CreateProduct(name, description string, price float64, imageURL string, size string) (*Product, error) {
	product := &Product{
		Name:        name,
		Description: description,
		Price:       price,
		ImageURL:    imageURL,
		Size:        size,
	}

	err := DB.QueryRow(context.Background(),
		"INSERT INTO products (name, description, price, image_url, size) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		product.Name, product.Description, product.Price, product.ImageURL, product.Size).Scan(&product.ID)

	if err != nil {
		return nil, err
	}

	return product, nil
}

func GetProducts() ([]*Product, error) {
	rows, err := DB.Query(context.Background(), "SELECT id, name, description, price, image_url, COALESCE(size, '') FROM products")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []*Product
	for rows.Next() {
		product := &Product{}
		err := rows.Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL, &product.Size)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}

	return products, nil
}

func SaveUserAddress(userID int, address string) error {
	address = strings.TrimSpace(address)
	if address == "" {
		return errors.New("address cannot be empty")
	}
	_, err := DB.Exec(context.Background(), `
        INSERT INTO user_addresses (user_id, address, created_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (user_id) DO UPDATE SET address = EXCLUDED.address, created_at = NOW()
    `, userID, address)
	return err
}

func GetUserAddress(userID int) (string, error) {
	var address string
	err := DB.QueryRow(context.Background(), `
        SELECT address FROM user_addresses WHERE user_id = $1
    `, userID).Scan(&address)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return address, nil
}

func ClearUserAddress(userID int) error {
	_, err := DB.Exec(context.Background(), `
        DELETE FROM user_addresses WHERE user_id = $1
    `, userID)
	return err
}

func GetUserSavedAddresses(userID int) ([]*UserSavedAddress, error) {
	rows, err := DB.Query(context.Background(), `
        SELECT id, user_id, address, created_at
        FROM user_saved_addresses
        WHERE user_id = $1
        ORDER BY created_at DESC, id DESC
    `, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var addresses []*UserSavedAddress
	for rows.Next() {
		item := &UserSavedAddress{}
		if err := rows.Scan(&item.ID, &item.UserID, &item.Address, &item.CreatedAt); err != nil {
			return nil, err
		}
		addresses = append(addresses, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return addresses, nil
}

func AddUserSavedAddress(userID int, address string) (*UserSavedAddress, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, errors.New("address cannot be empty")
	}

	item := &UserSavedAddress{}
	err := DB.QueryRow(context.Background(), `
        INSERT INTO user_saved_addresses (user_id, address)
        VALUES ($1, $2)
        RETURNING id, user_id, address, created_at
    `, userID, address).Scan(&item.ID, &item.UserID, &item.Address, &item.CreatedAt)
	if err != nil {
		return nil, err
	}

	return item, nil
}

func DeleteUserSavedAddress(userID, addressID int) error {
	result, err := DB.Exec(context.Background(), `
        DELETE FROM user_saved_addresses WHERE id = $1 AND user_id = $2
    `, addressID, userID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func GetHomeHighlightProducts(limit int) ([]*Product, error) {
	query := `
        SELECT p.id, p.name, p.description, p.price, p.image_url, COALESCE(p.size, '')
        FROM home_highlights h
        JOIN products p ON p.id = h.product_id
        ORDER BY h.position ASC, h.created_at DESC, h.id ASC
    `
	var rows pgx.Rows
	var err error
	if limit > 0 {
		rows, err = DB.Query(context.Background(), query+" LIMIT $1", limit)
	} else {
		rows, err = DB.Query(context.Background(), query)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []*Product
	for rows.Next() {
		p := &Product{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.ImageURL, &p.Size); err != nil {
			return nil, err
		}
		products = append(products, p)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return products, nil
}

func AddHomeHighlight(productID int) error {
	if productID <= 0 {
		return errors.New("invalid product id")
	}

	if err := EnsureProductExists(productID); err != nil {
		return err
	}

	var exists bool
	if err := DB.QueryRow(context.Background(), `
        SELECT EXISTS(SELECT 1 FROM home_highlights WHERE product_id = $1)
    `, productID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}

	var count int
	if err := DB.QueryRow(context.Background(), `
        SELECT COUNT(*) FROM home_highlights
    `).Scan(&count); err != nil {
		return err
	}
	if count >= 10 {
		return errors.New("highlight limit reached")
	}

	_, err := DB.Exec(context.Background(), `
        INSERT INTO home_highlights (product_id, position)
        VALUES ($1, COALESCE((SELECT MAX(position) + 1 FROM home_highlights), 0))
        ON CONFLICT (product_id) DO NOTHING
    `, productID)
	return err
}

func RemoveHomeHighlight(productID int) error {
	if productID <= 0 {
		return errors.New("invalid product id")
	}
	_, err := DB.Exec(context.Background(), `
        DELETE FROM home_highlights WHERE product_id = $1
    `, productID)
	return err
}

func GetMenuSectionImages() (map[string]string, error) {
	rows, err := DB.Query(context.Background(), `
        SELECT section, image_url FROM menu_section_images
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var section, imageURL string
		if err := rows.Scan(&section, &imageURL); err != nil {
			return nil, err
		}
		result[strings.TrimSpace(section)] = strings.TrimSpace(imageURL)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func SetMenuSectionImage(section, imageURL string) error {
	section = strings.TrimSpace(strings.ToLower(section))
	imageURL = strings.TrimSpace(imageURL)
	if section == "" || imageURL == "" {
		return errors.New("section and image url required")
	}

	_, err := DB.Exec(context.Background(), `
        INSERT INTO menu_section_images (section, image_url, updated_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (section)
        DO UPDATE SET image_url = EXCLUDED.image_url, updated_at = NOW()
    `, section, imageURL)
	return err
}

func GetRecentProducts(limit int) ([]*Product, error) {
	if limit <= 0 {
		limit = 4
	}
	rows, err := DB.Query(context.Background(), "SELECT id, name, description, price, image_url, COALESCE(size, '') FROM products ORDER BY id DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []*Product
	for rows.Next() {
		product := &Product{}
		err := rows.Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL, &product.Size)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return products, nil
}

func SearchProducts(query string, limit int) ([]*Product, error) {
	if limit <= 0 {
		limit = 4
	}
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return GetRecentProducts(limit)
	}

	pattern := "%" + trimmed + "%"
	rows, err := DB.Query(context.Background(), `
        SELECT id, name, description, price, image_url, COALESCE(size, '')
        FROM products
        WHERE name ILIKE $1 OR description ILIKE $1
        ORDER BY id DESC
        LIMIT $2
    `, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []*Product
	for rows.Next() {
		product := &Product{}
		err := rows.Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL, &product.Size)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return products, nil
}

func GetProductByID(id int) (*Product, error) {
	product := &Product{}
	err := DB.QueryRow(context.Background(),
		"SELECT id, name, description, price, image_url, COALESCE(size, '') FROM products WHERE id = $1",
		id).Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL, &product.Size)
	if err != nil {
		return nil, err
	}
	return product, nil
}

func DeleteProduct(id int) error {
	_, err := DB.Exec(context.Background(), "DELETE FROM products WHERE id = $1", id)
	return err
}

func CreateBannerImage(imageURL string) (*BannerImage, error) {
	banner := &BannerImage{
		ImageURL: imageURL,
	}
	err := DB.QueryRow(context.Background(),
		"INSERT INTO banner_images (image_url) VALUES ($1) RETURNING id",
		banner.ImageURL).Scan(&banner.ID)
	if err != nil {
		return nil, err
	}
	return banner, nil
}

func GetBannerImages() ([]*BannerImage, error) {
	rows, err := DB.Query(context.Background(),
		"SELECT id, image_url FROM banner_images ORDER BY created_at ASC, id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var banners []*BannerImage
	for rows.Next() {
		item := &BannerImage{}
		if err := rows.Scan(&item.ID, &item.ImageURL); err != nil {
			return nil, err
		}
		banners = append(banners, item)
	}

	return banners, nil
}

func DeleteBannerImage(id int) error {
	_, err := DB.Exec(context.Background(), "DELETE FROM banner_images WHERE id = $1", id)
	return err
}

func (p *Product) GalleryImages() []string {
	if p == nil {
		return nil
	}

	raw := strings.TrimSpace(p.ImageURL)
	if raw == "" {
		return nil
	}

	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})

	var images []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			images = append(images, part)
		}
	}

	if len(images) == 0 && raw != "" {
		return []string{raw}
	}

	return images
}

func (p *Product) PrimaryImage() string {
	images := p.GalleryImages()
	if len(images) > 0 {
		return images[0]
	}
	return ""
}

func (p *Product) SizeOptions() []string {
	if p == nil {
		return nil
	}

	parts := strings.FieldsFunc(p.Size, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})

	var sizes []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			sizes = append(sizes, part)
		}
	}
	return sizes
}

func AddFavorite(userID, productID int) error {
	_, err := DB.Exec(context.Background(),
		"INSERT INTO favorites (user_id, product_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		userID, productID)
	return err
}

func RemoveFavorite(userID, productID int) error {
	_, err := DB.Exec(context.Background(),
		"DELETE FROM favorites WHERE user_id = $1 AND product_id = $2",
		userID, productID)
	return err
}

func IsFavoriteProduct(userID, productID int) (bool, error) {
	var exists bool
	err := DB.QueryRow(context.Background(),
		"SELECT EXISTS (SELECT 1 FROM favorites WHERE user_id = $1 AND product_id = $2)",
		userID, productID).Scan(&exists)
	return exists, err
}

func GetFavoriteProductIDs(userID int) (map[int]bool, error) {
	rows, err := DB.Query(context.Background(),
		"SELECT product_id FROM favorites WHERE user_id = $1",
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int]bool)
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result[id] = true
	}
	return result, nil
}

func GetFavoriteProducts(userID int) ([]*Product, error) {
	rows, err := DB.Query(context.Background(),
		`SELECT p.id, p.name, p.description, p.price, p.image_url, COALESCE(p.size, '')
         FROM favorites f 
         JOIN products p ON p.id = f.product_id
         WHERE f.user_id = $1
         ORDER BY f.created_at DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []*Product
	for rows.Next() {
		p := &Product{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.ImageURL, &p.Size); err != nil {
			return nil, err
		}
		products = append(products, p)
	}
	return products, nil
}

func EnsureProductExists(productID int) error {
	var id int
	err := DB.QueryRow(context.Background(),
		"SELECT id FROM products WHERE id = $1",
		productID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("product not found")
	}
	return err
}

type CartItem struct {
	Product  *Product
	Quantity int
	Size     string
}

type Order struct {
	ID           int
	UserID       int
	Total        float64
	DeliveryType string
	PickupPoint  string
	Address      string
	CreatedAt    time.Time
}

type OrderItem struct {
	ID              int
	OrderID         int
	ProductID       int
	ProductName     string
	ProductPrice    float64
	Size            string
	Quantity        int
	ProductImageURL string
}

type OrderDetail struct {
	Order *Order
	Items []*OrderItem
}

func AddCartItem(userID, productID int, size string) error {
	size = strings.TrimSpace(size)
	_, err := DB.Exec(context.Background(), `
        INSERT INTO cart_items (user_id, product_id, size, quantity)
        VALUES ($1, $2, $3, 1)
        ON CONFLICT (user_id, product_id, size)
        DO UPDATE SET quantity = cart_items.quantity + 1,
                      created_at = NOW()
    `, userID, productID, size)
	return err
}

func DecrementCartItem(userID, productID int, size string) error {
	size = strings.TrimSpace(size)
	_, err := DB.Exec(context.Background(), `
        WITH decremented AS (
            UPDATE cart_items
            SET quantity = quantity - 1,
                created_at = NOW()
            WHERE user_id = $1 AND product_id = $2 AND size = $3 AND quantity > 1
            RETURNING 1
        )
        DELETE FROM cart_items
        WHERE user_id = $1 AND product_id = $2 AND size = $3
          AND NOT EXISTS (SELECT 1 FROM decremented)
    `, userID, productID, size)
	return err
}

func RemoveCartItem(userID, productID int, size string) error {
	size = strings.TrimSpace(size)
	_, err := DB.Exec(context.Background(),
		"DELETE FROM cart_items WHERE user_id = $1 AND product_id = $2 AND size = $3",
		userID, productID, size)
	return err
}

func GetCartItems(userID int) ([]*CartItem, error) {
	rows, err := DB.Query(context.Background(), `
        SELECT p.id, p.name, p.description, p.price, p.image_url, COALESCE(p.size, ''), ci.size, ci.quantity
        FROM cart_items ci
        JOIN products p ON p.id = ci.product_id
        WHERE ci.user_id = $1
        ORDER BY ci.created_at DESC
    `, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*CartItem
	for rows.Next() {
		product := &Product{}
		item := &CartItem{Product: product}
		if err := rows.Scan(&product.ID, &product.Name, &product.Description, &product.Price, &product.ImageURL, &product.Size, &item.Size, &item.Quantity); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func CreateOrderWithItems(userID int, items []*CartItem, deliveryType, pickupPoint, address string) (detail *OrderDetail, err error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("cart is empty")
	}

	ctx := context.Background()
	tx, err := DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		} else {
			if commitErr := tx.Commit(ctx); commitErr != nil {
				err = commitErr
			}
		}
	}()

	trimmedDeliveryType := strings.TrimSpace(deliveryType)
	if trimmedDeliveryType == "" {
		trimmedDeliveryType = "pickup"
	}
	trimmedPickup := strings.TrimSpace(pickupPoint)
	trimmedAddress := strings.TrimSpace(address)

	var computedTotal float64
	for _, item := range items {
		if item == nil || item.Product == nil {
			continue
		}
		computedTotal += item.Product.Price * float64(item.Quantity)
	}

	order := &Order{
		UserID:       userID,
		Total:        computedTotal,
		DeliveryType: trimmedDeliveryType,
		PickupPoint:  trimmedPickup,
		Address:      trimmedAddress,
	}

	err = tx.QueryRow(ctx, `
        INSERT INTO orders (user_id, total, delivery_type, pickup_point, address)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, created_at
    `, order.UserID, order.Total, order.DeliveryType, nullString(order.PickupPoint), nullString(order.Address)).Scan(&order.ID, &order.CreatedAt)
	if err != nil {
		return nil, err
	}

	var orderItems []*OrderItem
	for _, cartItem := range items {
		if cartItem == nil || cartItem.Product == nil {
			continue
		}
		orderItem := &OrderItem{
			OrderID:         order.ID,
			ProductID:       cartItem.Product.ID,
			ProductName:     cartItem.Product.Name,
			ProductPrice:    cartItem.Product.Price,
			Size:            cartItem.Size,
			Quantity:        cartItem.Quantity,
			ProductImageURL: strings.TrimSpace(cartItem.Product.ImageURL),
		}
		err = tx.QueryRow(ctx, `
            INSERT INTO order_items (order_id, product_id, product_name, product_price, size, quantity)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
        `, orderItem.OrderID, orderItem.ProductID, orderItem.ProductName, orderItem.ProductPrice, orderItem.Size, orderItem.Quantity).Scan(&orderItem.ID)
		if err != nil {
			return nil, err
		}
		orderItems = append(orderItems, orderItem)
	}
	if len(orderItems) == 0 {
		return nil, fmt.Errorf("order has no items")
	}

	_, err = tx.Exec(ctx, "DELETE FROM cart_items WHERE user_id = $1", userID)
	if err != nil {
		return nil, err
	}

	return &OrderDetail{Order: order, Items: orderItems}, nil
}

func nullString(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func GetCartItemQuantity(userID, productID int, size string) (int, bool, error) {
	size = strings.TrimSpace(size)
	var quantity int
	err := DB.QueryRow(context.Background(),
		"SELECT quantity FROM cart_items WHERE user_id = $1 AND product_id = $2 AND size = $3",
		userID, productID, size).Scan(&quantity)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return quantity, true, nil
}

func fetchOrderDetails(query string, args ...interface{}) ([]*OrderDetail, error) {
	rows, err := DB.Query(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	orderMap := make(map[int]*OrderDetail)
	var orderedKeys []int

	for rows.Next() {
		var ord Order
		var item OrderItem
		err := rows.Scan(&ord.ID, &ord.UserID, &ord.Total, &ord.DeliveryType, &ord.PickupPoint, &ord.Address, &ord.CreatedAt,
			&item.ID, &item.ProductID, &item.ProductName, &item.ProductPrice, &item.Size, &item.Quantity, &item.ProductImageURL)
		if err != nil {
			return nil, err
		}
		item.OrderID = ord.ID
		ord.DeliveryType = strings.TrimSpace(ord.DeliveryType)
		ord.PickupPoint = strings.TrimSpace(ord.PickupPoint)
		ord.Address = strings.TrimSpace(ord.Address)
		item.ProductImageURL = strings.TrimSpace(item.ProductImageURL)

		detail, exists := orderMap[ord.ID]
		if !exists {
			orderCopy := ord
			detail = &OrderDetail{
				Order: &orderCopy,
			}
			orderMap[ord.ID] = detail
			orderedKeys = append(orderedKeys, ord.ID)
		}
		itemCopy := item
		detail.Items = append(detail.Items, &itemCopy)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	results := make([]*OrderDetail, 0, len(orderedKeys))
	for _, id := range orderedKeys {
		if detail, ok := orderMap[id]; ok {
			results = append(results, detail)
		}
	}
	return results, nil
}

func GetOrdersByUser(userID int) ([]*OrderDetail, error) {
	return fetchOrderDetails(`
        SELECT o.id, o.user_id, o.total, o.delivery_type, COALESCE(o.pickup_point, ''), COALESCE(o.address, ''), o.created_at,
               oi.id, oi.product_id, oi.product_name, oi.product_price, oi.size, oi.quantity, COALESCE(p.image_url, '')
        FROM orders o
        JOIN order_items oi ON oi.order_id = o.id
        LEFT JOIN products p ON p.id = oi.product_id
        WHERE o.user_id = $1
        ORDER BY o.created_at DESC, oi.id ASC
    `, userID)
}

func GetAllOrders() ([]*OrderDetail, error) {
	return fetchOrderDetails(`
        SELECT o.id, o.user_id, o.total, o.delivery_type, COALESCE(o.pickup_point, ''), COALESCE(o.address, ''), o.created_at,
               oi.id, oi.product_id, oi.product_name, oi.product_price, oi.size, oi.quantity, COALESCE(p.image_url, '')
        FROM orders o
        JOIN order_items oi ON oi.order_id = o.id
        LEFT JOIN products p ON p.id = oi.product_id
        ORDER BY o.created_at DESC, oi.id ASC
    `)
}

func GetCartItemCount(userID int) (int, error) {
	var count int
	err := DB.QueryRow(context.Background(),
		"SELECT COALESCE(SUM(quantity), 0) FROM cart_items WHERE user_id = $1",
		userID).Scan(&count)
	return count, err
}

func GetCartTotal(userID int) (float64, error) {
	var total float64
	err := DB.QueryRow(context.Background(), `
        SELECT COALESCE(SUM(p.price * ci.quantity), 0)
        FROM cart_items ci
        JOIN products p ON p.id = ci.product_id
        WHERE ci.user_id = $1
    `, userID).Scan(&total)
	return total, err
}

func GetFavoriteCount(userID int) (int, error) {
	var count int
	err := DB.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM favorites WHERE user_id = $1",
		userID).Scan(&count)
	return count, err
}
