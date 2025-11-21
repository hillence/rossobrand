package database

import (
	"context"
	"errors"
	"fmt"
)

type productSeed struct {
	Name        string
	Description string
	Price       float64
	ImageURL    string
	Size        string
}

var defaultProductSeeds = []productSeed{
	{
		Name:        "Базовый тренч",
		Description: "Лаконичный двубортный тренч с поясом и шлицей на спине.",
		Price:       12990,
		ImageURL:    "https://images.unsplash.com/photo-1487412720507-e7ab37603c6f?w=1200",
		Size:        "XS,S,M,L",
	},
	{
		Name:        "Черное пальто",
		Description: "Утепленное пальто прямого силуэта с аккуратным воротником.",
		Price:       18990,
		ImageURL:    "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=1200",
		Size:        "S,M,L,XL",
	},
	{
		Name:        "Пуховик оверсайз",
		Description: "Легкий, но теплый пуховик оверсайз с высоким воротом.",
		Price:       15990,
		ImageURL:    "https://images.unsplash.com/photo-1524504388940-b1c1722653e1?w=1200",
		Size:        "XS,S,M,L",
	},
	{
		Name:        "Минималистичное платье",
		Description: "Платье длины миди из плотного трикотажа с разрезом сзади.",
		Price:       8990,
		ImageURL:    "https://images.unsplash.com/photo-1503341455253-b2e723bb3dbb?w=1200",
		Size:        "XS,S,M",
	},
	{
		Name:        "Сумка-тоут",
		Description: "Жесткая сумка из экокожи с короткими ручками и карманами внутри.",
		Price:       6490,
		ImageURL:    "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=1200",
		Size:        "",
	},
	{
		Name:        "Белые кроссовки",
		Description: "Минималистичные кожаные кроссовки на удобной подошве.",
		Price:       7490,
		ImageURL:    "https://images.unsplash.com/photo-1549298916-b41d501d3772?w=1200",
		Size:        "36,37,38,39,40,41",
	},
	{
		Name:        "Кардиган крупной вязки",
		Description: "Объемный кардиган с текстурным узором и поясом.",
		Price:       7990,
		ImageURL:    "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=900",
		Size:        "XS,S,M,L",
	},
	{
		Name:        "Замшевые перчатки",
		Description: "Мягкие замшевые перчатки c подкладкой из шерсти.",
		Price:       2990,
		ImageURL:    "https://images.unsplash.com/photo-1522312346375-d1a52e2b99b3?w=900",
		Size:        "S,M,L",
	},
}

var defaultBannerImages = []string{
	"https://images.unsplash.com/photo-1490114538077-0a7f8cb49891?w=1920",
	"https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?w=1920",
	"https://images.unsplash.com/photo-1483985988355-763728e1935b?w=1920",
}

// SeedDefaults ensures that the storefront always has enough content
// to render a meaningful home page even in a pristine database.
func SeedDefaults() error {
	if DB == nil {
		return errors.New("database connection is not initialized")
	}

	ctx := context.Background()

	if err := seedProducts(ctx); err != nil {
		return err
	}
	if err := seedBanners(ctx); err != nil {
		return err
	}
	if err := seedHighlights(ctx); err != nil {
		return err
	}
	return nil
}

func seedProducts(ctx context.Context) error {
	var count int
	if err := DB.QueryRow(ctx, "SELECT COUNT(*) FROM products").Scan(&count); err != nil {
		return fmt.Errorf("count products: %w", err)
	}
	if count > 0 {
		return nil
	}

	for _, product := range defaultProductSeeds {
		if _, err := DB.Exec(ctx, `
            INSERT INTO products (name, description, price, image_url, size)
            VALUES ($1, $2, $3, $4, $5)
        `, product.Name, product.Description, product.Price, product.ImageURL, product.Size); err != nil {
			return fmt.Errorf("insert default product %q: %w", product.Name, err)
		}
	}
	return nil
}

func seedBanners(ctx context.Context) error {
	var count int
	if err := DB.QueryRow(ctx, "SELECT COUNT(*) FROM banner_images").Scan(&count); err != nil {
		return fmt.Errorf("count banners: %w", err)
	}
	if count > 0 {
		return nil
	}

	for _, url := range defaultBannerImages {
		if _, err := DB.Exec(ctx, `
            INSERT INTO banner_images (image_url)
            VALUES ($1)
        `, url); err != nil {
			return fmt.Errorf("insert default banner: %w", err)
		}
	}
	return nil
}

func seedHighlights(ctx context.Context) error {
	var count int
	if err := DB.QueryRow(ctx, "SELECT COUNT(*) FROM home_highlights").Scan(&count); err != nil {
		return fmt.Errorf("count highlights: %w", err)
	}
	if count > 0 {
		return nil
	}

	rows, err := DB.Query(ctx, `
        SELECT id FROM products ORDER BY id ASC LIMIT 6
    `)
	if err != nil {
		return fmt.Errorf("select products for highlight: %w", err)
	}
	defer rows.Close()

	position := 0
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan product id: %w", err)
		}
		if _, err := DB.Exec(ctx, `
            INSERT INTO home_highlights (product_id, position)
            VALUES ($1, $2)
        `, id, position); err != nil {
			return fmt.Errorf("insert highlight: %w", err)
		}
		position++
	}
	return rows.Err()
}
