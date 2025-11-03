package wildberries

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	sellerListURL = "https://card.wb.ru/cards/list"
	detailURL     = "https://card.wb.ru/cards/detail"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

type listResponse struct {
	Data struct {
		Products []listProduct `json:"products"`
	} `json:"data"`
}

type listProduct struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Brand      string `json:"brand"`
	PriceU     int    `json:"priceU"`
	SalePriceU int    `json:"salePriceU"`
	Pics       int    `json:"pics"`
	Desc       string `json:"description"`
}

type detailResponse struct {
	Data struct {
		Products []struct {
			ID          int    `json:"id"`
			Description string `json:"description"`
		} `json:"products"`
	} `json:"data"`
}

type Product struct {
	Name        string
	Description string
	Price       float64
	ImageURL    string
}

func FetchSellerProducts(ctx context.Context, sellerID string) ([]Product, error) {
	sellerID = strings.TrimSpace(sellerID)
	if sellerID == "" {
		return nil, fmt.Errorf("нужно указать номер магазина")
	}
	if _, err := strconv.Atoi(sellerID); err != nil {
		return nil, fmt.Errorf("номер магазина должен содержать только цифры")
	}

	var results []Product
	for page := 1; page <= 20; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, sellerListURL, nil)
		if err != nil {
			return nil, err
		}

		q := req.URL.Query()
		q.Set("appType", "1")
		q.Set("curr", "rub")
		q.Set("dest", "-1257786")
		q.Set("reg", "0")
		q.Set("sort", "popular")
		q.Set("spp", "0")
		q.Set("supplier", sellerID)
		q.Set("page", strconv.Itoa(page))
		req.URL.RawQuery = q.Encode()

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("wildberries list request failed with status %d", resp.StatusCode)
		}

		var lr listResponse
		if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		if len(lr.Data.Products) == 0 {
			break
		}

		for _, item := range lr.Data.Products {
			description := strings.TrimSpace(item.Desc)
			if description == "" {
				if text, err := fetchProductDescription(ctx, item.ID); err == nil {
					description = text
				}
			}
			price := float64(item.SalePriceU)
			if price <= 0 {
				price = float64(item.PriceU)
			}
			if price > 0 {
				price = price / 100
			}

			results = append(results, Product{
				Name:        strings.TrimSpace(item.Name),
				Description: buildDescription(item.Brand, description),
				Price:       price,
				ImageURL:    buildImageURL(item.ID),
			})
		}

		if len(lr.Data.Products) < 100 {
			break
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("не удалось загрузить товары продавца")
	}

	return results, nil
}

func fetchProductDescription(ctx context.Context, productID int) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, detailURL, nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	q.Set("appType", "1")
	q.Set("curr", "rub")
	q.Set("dest", "-1257786")
	q.Set("spp", "0")
	q.Set("nm", strconv.Itoa(productID))
	req.URL.RawQuery = q.Encode()

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("wildberries detail request failed with status %d", resp.StatusCode)
	}

	var dr detailResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return "", err
	}
	if len(dr.Data.Products) == 0 {
		return "", fmt.Errorf("пустой ответ карточки товара")
	}
	return strings.TrimSpace(dr.Data.Products[0].Description), nil
}

func buildImageURL(productID int) string {
	if productID <= 0 {
		return ""
	}
	bucket := (productID / 100000) * 100000
	if bucket <= 0 {
		bucket = productID
	}
	return fmt.Sprintf("https://images.wbstatic.net/big/new/%d/%d-1.jpg", bucket, productID)
}

func buildDescription(brand, detail string) string {
	brand = strings.TrimSpace(brand)
	detail = strings.TrimSpace(detail)

	switch {
	case brand != "" && detail != "":
		return fmt.Sprintf("%s\n\n%s", brand, detail)
	case detail != "":
		return detail
	case brand != "":
		return brand
	default:
		return "Товар импортирован из Wildberries"
	}
}
