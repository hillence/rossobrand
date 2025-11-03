package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime/multipart"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gogo/database"
	"gogo/templates"
	"gogo/wildberries"

	"github.com/a-h/templ"
	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"golang.org/x/crypto/bcrypt"
)

func formatCartItemLabel(count int) string {
	abs := count % 100
	if abs >= 11 && abs <= 14 {
		return fmt.Sprintf("%d товаров", count)
	}
	switch count % 10 {
	case 1:
		return fmt.Sprintf("%d товар", count)
	case 2, 3, 4:
		return fmt.Sprintf("%d товара", count)
	default:
		return fmt.Sprintf("%d товаров", count)
	}
}

func formatCartTotal(total float64) string {
	value := strconv.FormatFloat(total, 'f', 2, 64)
	if strings.Contains(value, ".") {
		value = strings.TrimRight(strings.TrimRight(value, "0"), ".")
	}
	if value == "" {
		return "0"
	}
	return value
}

func saveUploadedFile(c *fiber.Ctx, fileHeader *multipart.FileHeader) (string, error) {
	if fileHeader == nil {
		return "", fmt.Errorf("no file provided")
	}
	uploadDir := filepath.Join("static", "image", "upload")
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return "", err
	}
	ext := strings.ToLower(filepath.Ext(fileHeader.Filename))
	if ext == "" {
		ext = ".jpg"
	}
	filename := uuid.NewString() + ext
	targetPath := filepath.Join(uploadDir, filename)
	if err := c.SaveFile(fileHeader, targetPath); err != nil {
		return "", err
	}
	return "/static/image/upload/" + filename, nil
}

func main() {
	if err := run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func run() error {
	const (
		adminEmail        = "hillence@yahoo.com"
		adminPasswordHash = "$2a$10$dhTWmLt9nOehAq.NqJC5ruwGWrjX8ooupQGIiMSBhwxZogTcGMtfe"
	)

	// IMPORTANT: Replace with your actual database connection string
	if err := database.Connect(); err != nil {
		return err
	}
	defer database.Close()

	if err := database.Migrate(); err != nil {
		return err
	}

	// Ensure admin user exists with expected credentials
	adminUser, err := database.GetUserByEmail(adminEmail)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if _, err := database.CreateUserWithHash(adminEmail, adminPasswordHash, "Hillence", "Admin", true); err != nil {
				return err
			}
		} else {
			return err
		}
	} else if adminUser.PasswordHash != adminPasswordHash {
		if err := database.UpdateUserPasswordHash(adminUser.ID, adminPasswordHash); err != nil {
			return err
		}
	}

	app := fiber.New()

	app.Use("/a9s5-panel/login", limiter.New(limiter.Config{
		Max:        5,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return fiber.NewError(fiber.StatusTooManyRequests, "Слишком много попыток входа, попробуйте позже.")
		},
	}))

	app.Get("/robots.txt", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/plain; charset=utf-8")
		return c.SendString("User-agent: *\nDisallow: /a9s5-panel/\n")
	})

	app.Get("/", func(c *fiber.Ctx) error {
		products, err := database.GetProducts()
		if err != nil {
			return err
		}
		banners, err := database.GetBannerImages()
		if err != nil {
			return err
		}
		newArrivals, err := database.GetHomeHighlightProducts(10)
		if err != nil {
			return err
		}
		if len(newArrivals) < 10 {
			recent, err := database.GetRecentProducts(10)
			if err != nil {
				return err
			}
			existing := make(map[int]struct{}, len(newArrivals))
			for _, p := range newArrivals {
				existing[p.ID] = struct{}{}
			}
			for _, p := range recent {
				if len(newArrivals) >= 10 {
					break
				}
				if _, ok := existing[p.ID]; ok {
					continue
				}
				existing[p.ID] = struct{}{}
				newArrivals = append(newArrivals, p)
			}
		}
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		favorites := make(map[int]bool)
		if user != nil {
			if ids, err := database.GetFavoriteProductIDs(user.ID); err == nil {
				favorites = ids
			} else {
				return err
			}
		}
		productAdded := c.Query("product_added") == "true"
		isAuthenticated := user != nil
		return adaptor.HTTPHandler(templ.Handler(templates.Home(products, newArrivals, banners, productAdded, isAuthenticated, favorites)))(c)
	})

	app.Get("/search", func(c *fiber.Ctx) error {
		query := c.Query("q")
		products, err := database.SearchProducts(query, 4)
		if err != nil {
			return err
		}
		results := make([]fiber.Map, 0, len(products))
		for _, product := range products {
			results = append(results, fiber.Map{
				"id":        product.ID,
				"name":      product.Name,
				"price":     product.Price,
				"image_url": product.ImageURL,
				"url":       "/products/" + strconv.Itoa(product.ID),
			})
		}
		return c.JSON(fiber.Map{
			"results": results,
		})
	})

	app.Get("/products/:id", func(c *fiber.Ctx) error {
		idParam := c.Params("id")
		productID, err := strconv.Atoi(idParam)
		if err != nil || productID <= 0 {
			return fiber.ErrNotFound
		}

		product, err := database.GetProductByID(productID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fiber.ErrNotFound
			}
			return err
		}

		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		isAuthenticated := user != nil
		isFavorited := false
		if user != nil {
			isFavorited, err = database.IsFavoriteProduct(user.ID, productID)
			if err != nil {
				return err
			}
		}

		return adaptor.HTTPHandler(templ.Handler(templates.ProductDetail(product, isAuthenticated, isFavorited)))(c)
	})

	app.Get("/login", func(c *fiber.Ctx) error {
		return adaptor.HTTPHandler(templ.Handler(templates.Login()))(c)
	})

	app.Post("/login", func(c *fiber.Ctx) error {
		email := c.FormValue("email")
		password := c.FormValue("password")

		user, err := database.GetUserByEmail(email)
		if err != nil {
			return fiber.ErrUnauthorized
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			return fiber.ErrUnauthorized
		}

		c.Cookie(&fiber.Cookie{
			Name:     "session_token",
			Value:    user.Email,
			Expires:  time.Now().Add(24 * time.Hour),
			HTTPOnly: true,
		})

		return c.Redirect("/personal")
	})

	app.Get("/register", func(c *fiber.Ctx) error {
		return adaptor.HTTPHandler(templ.Handler(templates.Register()))(c)
	})

	app.Post("/register", func(c *fiber.Ctx) error {
		email := c.FormValue("email")
		password := c.FormValue("password")
		firstName := strings.TrimSpace(c.FormValue("first_name"))
		lastName := strings.TrimSpace(c.FormValue("last_name"))

		if firstName == "" || lastName == "" {
			return fiber.ErrBadRequest
		}

		if _, err := database.GetUserByEmail(email); err == nil {
			return fiber.ErrConflict
		}

		createdUser, err := database.CreateUser(email, password, firstName, lastName, false)
		if err != nil {
			return err
		}

		c.Cookie(&fiber.Cookie{
			Name:     "session_token",
			Value:    createdUser.Email,
			Expires:  time.Now().Add(24 * time.Hour),
			HTTPOnly: true,
		})

		return c.Redirect("/personal")
	})

	app.Get("/favorites", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Redirect("/login")
		}
		products, err := database.GetFavoriteProducts(user.ID)
		if err != nil {
			return err
		}
		favorites, err := database.GetFavoriteProductIDs(user.ID)
		if err != nil {
			return err
		}
		return adaptor.HTTPHandler(templ.Handler(templates.Favorites(products, favorites, true)))(c)
	})

	app.Get("/favorites/count", func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.JSON(fiber.Map{"count": 0})
		}
		count, err := database.GetFavoriteCount(user.ID)
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{"count": count})
	})

	app.Post("/favorites/:id/toggle", func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"favorited": false})
		}
		idParam := c.Params("id")
		productID, err := strconv.Atoi(idParam)
		if err != nil || productID <= 0 {
			return fiber.ErrBadRequest
		}
		if err := database.EnsureProductExists(productID); err != nil {
			return fiber.ErrNotFound
		}
		isFav, err := database.IsFavoriteProduct(user.ID, productID)
		if err != nil {
			return err
		}
		if isFav {
			if err := database.RemoveFavorite(user.ID, productID); err != nil {
				return err
			}
			return c.JSON(fiber.Map{"favorited": false})
		}
		if err := database.AddFavorite(user.ID, productID); err != nil {
			return err
		}
		return c.JSON(fiber.Map{"favorited": true})
	})

	app.Get("/cart/count", func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.JSON(fiber.Map{"count": 0, "total": 0})
		}
		count, err := database.GetCartItemCount(user.ID)
		if err != nil {
			return err
		}
		total, err := database.GetCartTotal(user.ID)
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{"count": count, "total": total})
	})

	app.Post("/cart/:id/add", func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"added": false})
		}
		idParam := c.Params("id")
		productID, err := strconv.Atoi(idParam)
		if err != nil || productID <= 0 {
			return fiber.ErrBadRequest
		}
		if err := database.EnsureProductExists(productID); err != nil {
			return fiber.ErrNotFound
		}
		var payload struct {
			Size string `json:"size"`
		}
		if len(c.Body()) > 0 {
			if err := json.Unmarshal(c.Body(), &payload); err != nil {
				return fiber.ErrBadRequest
			}
		}
		if err := database.AddCartItem(user.ID, productID, payload.Size); err != nil {
			return err
		}
		count, err := database.GetCartItemCount(user.ID)
		if err != nil {
			return err
		}
		total, err := database.GetCartTotal(user.ID)
		if err != nil {
			return err
		}
		quantity, exists, err := database.GetCartItemQuantity(user.ID, productID, payload.Size)
		if err != nil {
			return err
		}
		if !exists {
			quantity = 0
		}
		return c.JSON(fiber.Map{
			"added":         true,
			"cart_count":    count,
			"cart_total":    total,
			"item_quantity": quantity,
		})
	})

	app.Post("/cart/:id/decrement", func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"decremented": false})
		}
		idParam := c.Params("id")
		productID, err := strconv.Atoi(idParam)
		if err != nil || productID <= 0 {
			return fiber.ErrBadRequest
		}
		var payload struct {
			Size string `json:"size"`
		}
		if len(c.Body()) > 0 {
			if err := json.Unmarshal(c.Body(), &payload); err != nil {
				return fiber.ErrBadRequest
			}
		}
		if err := database.DecrementCartItem(user.ID, productID, payload.Size); err != nil {
			return err
		}
		count, err := database.GetCartItemCount(user.ID)
		if err != nil {
			return err
		}
		total, err := database.GetCartTotal(user.ID)
		if err != nil {
			return err
		}
		quantity, exists, err := database.GetCartItemQuantity(user.ID, productID, payload.Size)
		if err != nil {
			return err
		}
		if !exists {
			quantity = 0
		}
		return c.JSON(fiber.Map{
			"decremented":   true,
			"cart_count":    count,
			"cart_total":    total,
			"item_quantity": quantity,
		})
	})

	app.Post("/cart/:id/remove", func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"removed": false})
		}
		idParam := c.Params("id")
		productID, err := strconv.Atoi(idParam)
		if err != nil || productID <= 0 {
			return fiber.ErrBadRequest
		}
		var payload struct {
			Size string `json:"size"`
		}
		if len(c.Body()) > 0 {
			if err := json.Unmarshal(c.Body(), &payload); err != nil {
				return fiber.ErrBadRequest
			}
		}
		if err := database.RemoveCartItem(user.ID, productID, payload.Size); err != nil {
			return err
		}
		count, err := database.GetCartItemCount(user.ID)
		if err != nil {
			return err
		}
		total, err := database.GetCartTotal(user.ID)
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{
			"removed":       true,
			"cart_count":    count,
			"cart_total":    total,
			"item_quantity": 0,
		})
	})

	app.Get("/cart", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Redirect("/login")
		}
		items, err := database.GetCartItems(user.ID)
		if err != nil {
			return err
		}
		total, err := database.GetCartTotal(user.ID)
		if err != nil {
			return err
		}
		return adaptor.HTTPHandler(templ.Handler(templates.Cart(items, total, user != nil)))(c)
	})

	app.Get("/checkout/address", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Redirect("/login")
		}
		addresses, err := database.GetUserSavedAddresses(user.ID)
		if err != nil {
			return err
		}
		return adaptor.HTTPHandler(templ.Handler(templates.AddressBook(
			user != nil,
			addresses,
			true,
		)))(c)
	})

	app.Get("/address-book", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Redirect("/login")
		}
		addresses, err := database.GetUserSavedAddresses(user.ID)
		if err != nil {
			return err
		}
		return adaptor.HTTPHandler(templ.Handler(templates.AddressBook(
			user != nil,
			addresses,
			false,
		)))(c)
	})

	app.Post("/address-book/save", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return fiber.ErrUnauthorized
		}
		var payload struct {
			Address string `json:"address"`
		}
		if err := c.BodyParser(&payload); err != nil {
			return fiber.ErrBadRequest
		}
		item, err := database.AddUserSavedAddress(user.ID, payload.Address)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		if err := database.SaveUserAddress(user.ID, item.Address); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		return c.JSON(fiber.Map{
			"id":      item.ID,
			"address": item.Address,
		})
	})

	app.Post("/address-book/select", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return fiber.ErrUnauthorized
		}
		var payload struct {
			AddressID int `json:"address_id"`
		}
		if err := c.BodyParser(&payload); err != nil {
			return fiber.ErrBadRequest
		}
		if payload.AddressID <= 0 {
			return fiber.ErrBadRequest
		}
		addresses, err := database.GetUserSavedAddresses(user.ID)
		if err != nil {
			return err
		}
		var selected string
		for _, item := range addresses {
			if item != nil && item.ID == payload.AddressID {
				selected = item.Address
				break
			}
		}
		if strings.TrimSpace(selected) == "" {
			return fiber.ErrNotFound
		}
		if err := database.SaveUserAddress(user.ID, selected); err != nil {
			return err
		}
		return c.JSON(fiber.Map{"saved": true})
	})

	app.Get("/menu/sections", func(c *fiber.Ctx) error {
		images, err := database.GetMenuSectionImages()
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{"sections": images})
	})

	app.Delete("/address-book/:id", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return fiber.ErrUnauthorized
		}
		idParam := c.Params("id")
		addressID, err := strconv.Atoi(idParam)
		if err != nil || addressID <= 0 {
			return fiber.ErrBadRequest
		}
		if err := database.DeleteUserSavedAddress(user.ID, addressID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return c.SendStatus(fiber.StatusNotFound)
			}
			return err
		}
		addresses, err := database.GetUserSavedAddresses(user.ID)
		if err != nil {
			return err
		}
		if len(addresses) > 0 {
			if err := database.SaveUserAddress(user.ID, addresses[0].Address); err != nil {
				return err
			}
		} else {
			if err := database.ClearUserAddress(user.ID); err != nil {
				return err
			}
		}
		return c.SendStatus(fiber.StatusNoContent)
	})

	app.Get("/simplecheckout", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Redirect("/login")
		}
		items, err := database.GetCartItems(user.ID)
		if err != nil {
			return err
		}
		address, err := database.GetUserAddress(user.ID)
		if err != nil {
			return err
		}
		itemCount, err := database.GetCartItemCount(user.ID)
		if err != nil {
			return err
		}
		total, err := database.GetCartTotal(user.ID)
		if err != nil {
			return err
		}
		return adaptor.HTTPHandler(templ.Handler(templates.SimpleCheckout(
			user,
			address,
			items,
			formatCartItemLabel(itemCount),
			formatCartTotal(total),
			user != nil,
		)))(c)
	})

	app.Post("/orders/create", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Redirect("/login")
		}
		items, err := database.GetCartItems(user.ID)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return c.Redirect("/cart")
		}
		deliveryType := strings.TrimSpace(c.FormValue("delivery_type"))
		pickupPoint := strings.TrimSpace(c.FormValue("pickup_point"))
		addressValue := strings.TrimSpace(c.FormValue("address"))
		if strings.EqualFold(deliveryType, "pickup") && pickupPoint == "" {
			return c.Redirect("/simplecheckout?error=pickup_point")
		}
		detail, err := database.CreateOrderWithItems(user.ID, items, deliveryType, pickupPoint, addressValue)
		if err != nil {
			return err
		}
		return c.Redirect(fmt.Sprintf("/orders?created=%d", detail.Order.ID))
	})

	app.Get("/orders", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Redirect("/login")
		}
		orders, err := database.GetOrdersByUser(user.ID)
		if err != nil {
			return err
		}
		createdParam := strings.TrimSpace(c.Query("created"))
		if createdParam != "" {
			found := false
			for _, detail := range orders {
				if detail != nil && detail.Order != nil && strconv.Itoa(detail.Order.ID) == createdParam {
					found = true
					break
				}
			}
			if !found {
				createdParam = ""
			}
		}
		return adaptor.HTTPHandler(templ.Handler(templates.OrdersPage(orders, createdParam, user != nil)))(c)
	})

	app.Get("/a9s5-panel/login", func(c *fiber.Ctx) error {
		return adaptor.HTTPHandler(templ.Handler(templates.AdminLogin()))(c)
	})

	app.Post("/a9s5-panel/login", func(c *fiber.Ctx) error {
		email := strings.TrimSpace(c.FormValue("email"))
		password := c.FormValue("password")

		user, err := database.GetUserByEmail(email)
		if err != nil {
			return fiber.ErrUnauthorized
		}

		if !user.IsAdmin || !strings.EqualFold(user.Email, adminEmail) {
			return fiber.ErrUnauthorized
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			return fiber.ErrUnauthorized
		}

		c.Cookie(&fiber.Cookie{
			Name:     "admin_session",
			Value:    user.Email,
			Expires:  time.Now().Add(12 * time.Hour),
			HTTPOnly: true,
			Secure:   true,
		})

		return c.Redirect("/a9s5-panel/")
	})

	admin := app.Group("/a9s5-panel", AdminMiddleware(adminEmail))
	admin.Get("/", func(c *fiber.Ctx) error {
		dbProducts, err := database.GetProducts()
		if err != nil {
			return err
		}
		banners, err := database.GetBannerImages()
		if err != nil {
			return err
		}
		orders, err := database.GetAllOrders()
		if err != nil {
			return err
		}
		highlights, err := database.GetHomeHighlightProducts(0)
		if err != nil {
			return err
		}
		highlightSet := make(map[int]struct{}, len(highlights))
		for _, item := range highlights {
			if item != nil {
				highlightSet[item.ID] = struct{}{}
			}
		}
		highlightCandidates := make([]*database.Product, 0, len(dbProducts))
		for _, product := range dbProducts {
			if product == nil {
				continue
			}
			if _, exists := highlightSet[product.ID]; exists {
				continue
			}
			highlightCandidates = append(highlightCandidates, product)
		}
		menuImages, err := database.GetMenuSectionImages()
		if err != nil {
			return err
		}
		return adaptor.HTTPHandler(templ.Handler(templates.Admin(dbProducts, highlightCandidates, highlights, menuImages, banners, orders)))(c)
	})

	admin.Post("/menu-images", func(c *fiber.Ctx) error {
		section := strings.TrimSpace(c.FormValue("section"))
		if section == "" {
			return fiber.ErrBadRequest
		}
		fileHeader, err := c.FormFile("image")
		if err != nil || fileHeader == nil {
			return fiber.ErrBadRequest
		}
		savedURL, err := saveUploadedFile(c, fileHeader)
		if err != nil {
			return err
		}
		if err := database.SetMenuSectionImage(section, savedURL); err != nil {
			return err
		}
		return c.Redirect("/a9s5-panel/")
	})

	admin.Post("/highlights", func(c *fiber.Ctx) error {
		productID, err := strconv.Atoi(strings.TrimSpace(c.FormValue("product_id")))
		if err != nil || productID <= 0 {
			return fiber.ErrBadRequest
		}
		if err := database.AddHomeHighlight(productID); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		return c.Redirect("/a9s5-panel/")
	})

	admin.Post("/highlights/:id/delete", func(c *fiber.Ctx) error {
		idParam := strings.TrimSpace(c.Params("id"))
		productID, err := strconv.Atoi(idParam)
		if err != nil || productID <= 0 {
			return fiber.ErrBadRequest
		}
		if err := database.RemoveHomeHighlight(productID); err != nil {
			return err
		}
		return c.Redirect("/a9s5-panel/")
	})

	admin.Post("/logout", func(c *fiber.Ctx) error {
		c.Cookie(&fiber.Cookie{
			Name:     "admin_session",
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour),
			HTTPOnly: true,
			Secure:   true,
		})
		return c.Redirect("/a9s5-panel/login")
	})

	admin.Post("/products", func(c *fiber.Ctx) error {
		name := c.FormValue("name")
		description := c.FormValue("description")
		price := c.FormValue("price")
		size := c.FormValue("size")

		imageURL := strings.TrimSpace(c.FormValue("image_url"))
		imageHeader, fileErr := c.FormFile("image")
		if fileErr != nil && fileErr != fiber.ErrBadRequest && fileErr != fiber.ErrUnprocessableEntity {
			// Return unexpected errors; ignore missing file errors
			return fileErr
		}
		if imageHeader != nil {
			savedURL, err := saveUploadedFile(c, imageHeader)
			if err != nil {
				return err
			}
			imageURL = savedURL
		}

		if strings.TrimSpace(imageURL) == "" {
			return fiber.ErrBadRequest
		}

		priceFloat, err := strconv.ParseFloat(price, 64)
		if err != nil {
			return err
		}

		_, err = database.CreateProduct(name, description, priceFloat, imageURL, size)
		if err != nil {
			return err
		}

		return c.Redirect("/?product_added=true")
	})

	admin.Post("/products/:id/delete", func(c *fiber.Ctx) error {
		idParam := c.Params("id")
		productID, err := strconv.Atoi(idParam)
		if err != nil {
			return err
		}

		if err := database.DeleteProduct(productID); err != nil {
			return err
		}

		return c.Redirect("/a9s5-panel/")
	})

	admin.Post("/banners", func(c *fiber.Ctx) error {
		imageURL := strings.TrimSpace(c.FormValue("image_url"))
		bannerHeader, fileErr := c.FormFile("image")
		if fileErr != nil && fileErr != fiber.ErrBadRequest && fileErr != fiber.ErrUnprocessableEntity {
			return fileErr
		}
		if bannerHeader != nil {
			savedURL, err := saveUploadedFile(c, bannerHeader)
			if err != nil {
				return err
			}
			imageURL = savedURL
		}
		if imageURL == "" {
			return fiber.ErrBadRequest
		}

		if _, err := database.CreateBannerImage(imageURL); err != nil {
			return err
		}

		return c.Redirect("/a9s5-panel/")
	})

	admin.Post("/banners/:id/delete", func(c *fiber.Ctx) error {
		idParam := c.Params("id")
		bannerID, err := strconv.Atoi(idParam)
		if err != nil {
			return err
		}

		if err := database.DeleteBannerImage(bannerID); err != nil {
			return err
		}

		return c.Redirect("/a9s5-panel/")
	})

	admin.Post("/import/wb", func(c *fiber.Ctx) error {
		sellerID := strings.TrimSpace(c.FormValue("seller_id"))

		if sellerID == "" {
			return c.Redirect("/a9s5-panel/")
		}

		if _, err := strconv.Atoi(sellerID); err != nil {
			return c.Redirect("/a9s5-panel/")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		imported, err := wildberries.FetchSellerProducts(ctx, sellerID)
		if err != nil {
			log.Printf("wildberries import failed: %v", err)
			return c.Redirect("/a9s5-panel/")
		}

		existingProducts, err := database.GetProducts()
		if err != nil {
			return err
		}

		existing := make(map[string]struct{}, len(existingProducts))
		for _, p := range existingProducts {
			key := strings.ToLower(strings.TrimSpace(p.Name))
			if key != "" {
				existing[key] = struct{}{}
			}
		}

		added := 0
		for _, p := range imported {
			if p.Name == "" {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(p.Name))
			if _, found := existing[key]; found {
				continue
			}
			if p.Price <= 0 {
				continue
			}
			if _, err := database.CreateProduct(p.Name, p.Description, p.Price, p.ImageURL, ""); err != nil {
				log.Printf("wildberries save failed for %s: %v", p.Name, err)
				continue
			}
			existing[key] = struct{}{}
			added++
		}

		if added == 0 {
			log.Printf("wildberries import %s: no new products", sellerID)
		}

		return c.Redirect("/a9s5-panel/")
	})

	app.Post("/accept-cookies", func(c *fiber.Ctx) error {
		return c.SendString("")
	})

	app.Get("/personal", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Redirect("/login")
		}
		return adaptor.HTTPHandler(templ.Handler(templates.Personal(user)))(c)
	})

	app.Post("/personal/avatar", AuthMiddleware, func(c *fiber.Ctx) error {
		user, err := getCurrentUser(c)
		if err != nil {
			return err
		}
		if user == nil {
			return c.Redirect("/login")
		}

		fileHeader, err := c.FormFile("avatar")
		if err != nil || fileHeader == nil {
			return fiber.ErrBadRequest
		}

		avatarURL, err := saveUploadedFile(c, fileHeader)
		if err != nil {
			return err
		}

		if err := database.UpdateUserAvatar(user.ID, avatarURL); err != nil {
			return err
		}

		user.AvatarURL = avatarURL
		return c.Redirect("/personal")
	})

	app.Post("/logout", func(c *fiber.Ctx) error {
		c.Cookie(&fiber.Cookie{
			Name:     "session_token",
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour),
			HTTPOnly: true,
		})
		c.Cookie(&fiber.Cookie{
			Name:     "admin_session",
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour),
			HTTPOnly: true,
		})
		return c.Redirect("/")
	})

	app.Static("/static", "./static")

	if err := app.Listen(":3000"); err != nil {
		return err
	}
	return nil
}

func AdminMiddleware(adminEmail string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		email := strings.TrimSpace(c.Cookies("admin_session"))
		if email == "" {
			return c.Redirect("/a9s5-panel/login")
		}
		user, err := database.GetUserByEmail(email)
		if err != nil || user == nil {
			return c.Redirect("/a9s5-panel/login")
		}
		if !user.IsAdmin || !strings.EqualFold(user.Email, adminEmail) {
			return c.Redirect("/a9s5-panel/login")
		}
		c.Locals("currentAdmin", user)
		return c.Next()
	}
}

func AuthMiddleware(c *fiber.Ctx) error {
	user, err := getCurrentUser(c)
	if err != nil {
		return err
	}
	if user == nil {
		return c.Redirect("/login")
	}
	return c.Next()
}

func getCurrentUser(c *fiber.Ctx) (*database.User, error) {
	if cached := c.Locals("currentUser"); cached != nil {
		if user, ok := cached.(*database.User); ok {
			return user, nil
		}
	}

	token := c.Cookies("session_token")
	if token == "" {
		return nil, nil
	}

	user, err := database.GetUserByEmail(token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	c.Locals("currentUser", user)
	return user, nil
}
