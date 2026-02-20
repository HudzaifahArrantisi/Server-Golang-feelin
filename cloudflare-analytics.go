package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

// In-memory storage untuk webhook payment status
type PaymentStatus struct {
	OrderID       string    `json:"order_id"`
	Status        string    `json:"status"`
	Amount        int       `json:"amount"`
	PaymentMethod string    `json:"payment_method"`
	CompletedAt   string    `json:"completed_at"`
	ReceivedAt    time.Time `json:"received_at"`
}

var (
	paymentStatuses = make(map[string]*PaymentStatus)
	paymentMutex    sync.RWMutex
)

type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

type CloudflareResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
	Zone   string      `json:"zone,omitempty"`
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Allowed exact origins
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://localhost:5173",
			"https://feelin.my.id",
			"https://www.feelin.my.id",
		}

		allowed := ""
		for _, a := range allowedOrigins {
			if origin == a {
				allowed = a
				break
			}
		}

		// Allow preview Vercel domains like https://feelin-<hash>.vercel.app
		if allowed == "" && origin != "" {
			if strings.HasPrefix(origin, "https://feelin-") && strings.HasSuffix(origin, ".vercel.app") {
				allowed = origin
			}
		}

		if allowed != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowed)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-Cloudflare-Token, X-CF-Read-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		log.Printf("📨 %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next(w, r)
	}
}

// Handler untuk Cloudflare Analytics (GraphQL)
func cloudflareHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	zoneID := os.Getenv("ZONE_ID")
	// Allow optional token override from admin UI (sent via X-Cloudflare-Token header)
	token := r.Header.Get("X-Cloudflare-Token")
	if token == "" {
		token = os.Getenv("CLOUDFLARE_API_TOKEN")
	}

	log.Printf("🔍 Fetching analytics for zone: %s", zoneID)

	if zoneID == "" || token == "" {
		log.Printf("❌ Missing credentials")
		response := CloudflareResponse{
			Status: "error",
			Error:  "ZONE_ID atau CLOUDFLARE_API_TOKEN belum diatur di .env file (atau token tidak diberikan)",
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	query := `query GetZoneAnalytics($zoneTag: string, $datetimeStart: string, $datetimeEnd: string) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      zoneTag
      httpRequests1dGroups(
        orderBy: [date_DESC]
        limit: 7
        filter: {
          date_geq: $datetimeStart
          date_leq: $datetimeEnd
        }
      ) {
        dimensions {
          date
        }
        sum {
          bytes
          cachedBytes
          cachedRequests
          requests
          threats
        }
        uniq {
          uniques
        }
      }
    }
  }
}`

	now := time.Now().UTC()
	sevenDaysAgo := now.AddDate(0, 0, -7)
	dateStart := sevenDaysAgo.Format("2006-01-02")
	dateEnd := now.Format("2006-01-02")

	variables := map[string]interface{}{
		"zoneTag":       zoneID,
		"datetimeStart": dateStart,
		"datetimeEnd":   dateEnd,
	}

	log.Printf("Sending GraphQL query to Cloudflare...")
	log.Printf("Date range: %s to %s", dateStart, dateEnd)

	payload := GraphQLRequest{
		Query:     query,
		Variables: variables,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("❌ Failed to marshal payload: %v", err)
		response := CloudflareResponse{
			Status: "error",
			Error:  fmt.Sprintf("Gagal membuat payload: %v", err),
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	req, err := http.NewRequest("POST", "https://api.cloudflare.com/client/v4/graphql", bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		response := CloudflareResponse{
			Status: "error",
			Error:  fmt.Sprintf("Gagal membuat request: %v", err),
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		response := CloudflareResponse{
			Status: "error",
			Error:  fmt.Sprintf("Gagal mengirim request ke Cloudflare: %v", err),
		}
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(response)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		response := CloudflareResponse{
			Status: "error",
			Error:  fmt.Sprintf("Gagal membaca response: %v", err),
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	log.Printf("📥 Cloudflare Response Status: %d", resp.StatusCode)

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("Failed to parse JSON: %v", err)
		response := CloudflareResponse{
			Status: "error",
			Error:  fmt.Sprintf("Response dari Cloudflare bukan JSON valid: %v", err),
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	if errors, ok := result["errors"].([]interface{}); ok && len(errors) > 0 {
		errorMsg := "Unknown error from Cloudflare"
		var errorDetails []string

		for i, e := range errors {
			if errObj, ok := e.(map[string]interface{}); ok {
				if msg, ok := errObj["message"].(string); ok {
					errorDetails = append(errorDetails, fmt.Sprintf("Error %d: %s", i+1, msg))
					if i == 0 {
						errorMsg = msg
					}
				}
			}
		}

		log.Printf("Cloudflare API Errors:")
		for _, detail := range errorDetails {
			log.Printf("   - %s", detail)
		}

		fullErrorMsg := errorMsg
		if len(errorDetails) > 1 {
			fullErrorMsg = fmt.Sprintf("%s (dan %d error lainnya - lihat log server)", errorMsg, len(errorDetails)-1)
		}

		response := CloudflareResponse{
			Status: "error",
			Error:  fullErrorMsg,
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	log.Printf(" Analytics fetched successfully for zone: %s", zoneID)

	response := CloudflareResponse{
		Status: "success",
		Data:   result,
		Zone:   zoneID,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Cloudflare Radar functionality removed — use CF_READ_ALL_TOKEN-based endpoints only

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"status":    "healthy",
		"service":   "cloudflare-analytics-proxy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "4.0.0",
	}
	json.NewEncoder(w).Encode(response)
}

// /api/cf/debug — cek semua env var yang terbaca server (token di-mask aman)
func cfDebugHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	maskToken := func(t string) string {
		if t == "" {
			return "❌ KOSONG / TIDAK TERBACA"
		}
		if len(t) <= 8 {
			return "✅ ADA (terlalu pendek: " + t + ")"
		}
		return "✅ ADA → " + t[:4] + "****" + t[len(t)-4:]
	}

	cfToken := os.Getenv("CF_READ_ALL_TOKEN")
	analyticsToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	// CLOUDFLARE_RADAR_API_TOKEN intentionally removed from this project.
	zoneID := os.Getenv("ZONE_ID")

	// Coba panggil Cloudflare verify dengan token yang ada
	verifyStatus := "skip"
	if cfToken != "" {
		req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/user/tokens/verify", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+cfToken)
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				verifyStatus = "error: " + err.Error()
			} else {
				verifyStatus = fmt.Sprintf("HTTP %d", resp.StatusCode)
				resp.Body.Close()
			}
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"env_vars": map[string]string{
			"CF_READ_ALL_TOKEN":    maskToken(cfToken),
			"CLOUDFLARE_API_TOKEN": maskToken(analyticsToken),
			"ZONE_ID":              maskToken(zoneID),
		},
		"cloudflare_verify_test": verifyStatus,
		"hint":                   "Jika CF_READ_ALL_TOKEN KOSONG → pastikan file .env di root project berisi CF_READ_ALL_TOKEN=xxx lalu restart server",
	})
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	zoneID := os.Getenv("ZONE_ID")
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	readAllToken := os.Getenv("CF_READ_ALL_TOKEN")

	hasApiToken := apiToken != ""
	hasReadAll := readAllToken != ""

	maskedApiToken := ""
	if hasApiToken && len(apiToken) > 8 {
		maskedApiToken = apiToken[:4] + "..." + apiToken[len(apiToken)-4:]
	}

	maskedReadAll := ""
	if hasReadAll && len(readAllToken) > 8 {
		maskedReadAll = readAllToken[:4] + "..." + readAllToken[len(readAllToken)-4:]
	}

	response := map[string]interface{}{
		"service":              "Cloudflare Analytics Proxy",
		"status":               "running",
		"zone_id":              zoneID,
		"has_api_token":        hasApiToken,
		"api_token_masked":     maskedApiToken,
		"has_readall_token":    hasReadAll,
		"readall_token_masked": maskedReadAll,
		"timestamp":            time.Now().Format(time.RFC3339),
		"endpoints": map[string]string{
			"analytics": "/api/cloudflare-analytics",
			"health":    "/api/health",
			"test":      "/api/test",
		},
		"api_docs": map[string]string{
			"analytics": "https://developers.cloudflare.com/analytics/graphql-api/",
		},
	}
	json.NewEncoder(w).Encode(response)
}

// Pakasir API Request/Response structures
type PakasirRequest struct {
	OrderID       string `json:"order_id"`
	Amount        int    `json:"amount"`
	PaymentMethod string `json:"payment_method,omitempty"`
}

type PakasirAPIRequest struct {
	Project string `json:"project"`
	OrderID string `json:"order_id"`
	Amount  int    `json:"amount"`
	ApiKey  string `json:"api_key"`
}

// Handler untuk Pakasir Payment API (proxy to avoid CORS)
func pakasirHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// Read raw body for debugging
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("❌ Failed to read request body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read request body"})
		return
	}
	log.Printf("📥 Received request body: %s", string(bodyBytes))

	// Parse request body
	var reqBody PakasirRequest
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		log.Printf("❌ Failed to parse request body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body", "details": err.Error()})
		return
	}

	log.Printf("📦 Parsed request: order_id=%s, amount=%d", reqBody.OrderID, reqBody.Amount)

	if reqBody.OrderID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "order_id is required"})
		return
	}

	if reqBody.Amount <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "amount must be greater than 0"})
		return
	}

	paymentMethod := reqBody.PaymentMethod
	if paymentMethod == "" {
		paymentMethod = "qris"
	}

	// Pakasir API credentials
	pakasirProject := os.Getenv("PAKASIR_PROJECT")
	if pakasirProject == "" {
		pakasirProject = "feelin"
	}
	pakasirApiKey := os.Getenv("PAKASIR_API_KEY")
	if pakasirApiKey == "" {
		log.Printf("PAKASIR_API_KEY not set in environment")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Server misconfiguration"})
		return
	}

	log.Printf("📦 Creating Pakasir transaction: order=%s, amount=%d, method=%s", reqBody.OrderID, reqBody.Amount, paymentMethod)

	// Build Pakasir API request - using map for flexibility
	pakasirReq := map[string]interface{}{
		"project":  pakasirProject,
		"order_id": reqBody.OrderID,
		"amount":   reqBody.Amount,
		"api_key":  pakasirApiKey,
	}

	payloadBytes, err := json.Marshal(pakasirReq)
	if err != nil {
		log.Printf("❌ Failed to marshal Pakasir request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create request"})
		return
	}

	log.Printf("📤 Sending to Pakasir: %s", string(payloadBytes))

	// Call Pakasir API
	pakasirURL := fmt.Sprintf("https://app.pakasir.com/api/transactioncreate/%s", paymentMethod)
	log.Printf("📡 Pakasir URL: %s", pakasirURL)

	req, err := http.NewRequest("POST", pakasirURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Printf("❌ Failed to create Pakasir request: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create request"})
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ Pakasir API error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to connect to Pakasir API"})
		return
	}
	defer resp.Body.Close()

	// Read and forward the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Failed to read Pakasir response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read response"})
		return
	}

	log.Printf("✅ Pakasir response status: %d", resp.StatusCode)
	log.Printf("📥 Pakasir response body: %s", string(body))

	// Forward status code and body
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ═══════════════════════════════════════════════════════
// CF OVERVIEW PROXY HANDLERS (Read All Resources Token)
// Token dibaca dari env CF_READ_ALL_TOKEN atau header X-CF-Read-Token
// ═══════════════════════════════════════════════════════

// getReadAllToken: ambil token dari header dulu, fallback ke env
func getReadAllToken(r *http.Request) string {
	if t := r.Header.Get("X-CF-Read-Token"); t != "" {
		return t
	}
	return os.Getenv("CF_READ_ALL_TOKEN")
}

// cfGet: generic proxy GET ke Cloudflare REST API
func cfGet(w http.ResponseWriter, token, apiPath string) {
	w.Header().Set("Content-Type", "application/json")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "CF_READ_ALL_TOKEN belum diatur di .env root project",
		})
		return
	}
	url := "https://api.cloudflare.com/client/v4" + apiPath
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Gagal konek ke Cloudflare: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("📥 CF API [%s] status: %d", apiPath, resp.StatusCode)
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// GET /api/cf/verify
func cfVerifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	cfGet(w, getReadAllToken(r), "/user/tokens/verify")
}

// GET /api/cf/accounts
func cfAccountsHandler(w http.ResponseWriter, r *http.Request) {
	cfGet(w, getReadAllToken(r), "/accounts?per_page=10")
}

// GET /api/cf/zones
func cfZonesHandler(w http.ResponseWriter, r *http.Request) {
	cfGet(w, getReadAllToken(r), "/zones?per_page=20")
}

// GET /api/cf/dns?zone_id=xxx
func cfDNSHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "zone_id wajib diisi"})
		return
	}
	cfGet(w, getReadAllToken(r), "/zones/"+zoneID+"/dns_records?per_page=50&order=type")
}

// GET /api/cf/firewall?zone_id=xxx
func cfFirewallHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "zone_id wajib diisi"})
		return
	}
	cfGet(w, getReadAllToken(r), "/zones/"+zoneID+"/firewall/rules?per_page=20")
}

// GET /api/cf/pagerules?zone_id=xxx
func cfPageRulesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "zone_id wajib diisi"})
		return
	}
	cfGet(w, getReadAllToken(r), "/zones/"+zoneID+"/pagerules?status=active&per_page=20")
}

// GET /api/cf/ssl?zone_id=xxx — paralel fetch semua settings sekaligus
func cfSSLHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	token := getReadAllToken(r)
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "zone_id wajib diisi"})
		return
	}
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "CF_READ_ALL_TOKEN belum diatur"})
		return
	}

	fetchSetting := func(setting string) interface{} {
		url := "https://api.cloudflare.com/client/v4/zones/" + zoneID + "/settings/" + setting
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("Authorization", "Bearer "+token)
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		if res, ok := result["result"]; ok {
			return res
		}
		return nil
	}

	type kv struct {
		key string
		val interface{}
	}
	keys := []string{"ssl", "always_use_https", "min_tls_version", "http2", "brotli", "early_hints", "minify"}
	ch := make(chan kv, len(keys))
	for _, k := range keys {
		go func(key string) { ch <- kv{key, fetchSetting(key)} }(k)
	}
	results := map[string]interface{}{}
	for range keys {
		s := <-ch
		results[s.key] = s.val
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "result": results})
}

// GET /api/cf/waf?zone_id=xxx — WAF custom rules (newer API)
func cfWAFHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "zone_id wajib diisi"})
		return
	}
	cfGet(w, getReadAllToken(r), "/zones/"+zoneID+"/rulesets?phase=http_request_firewall_custom")
}

// PakasirWebhookPayload struktur untuk menerima webhook dari Pakasir
type PakasirWebhookPayload struct {
	OrderID       string `json:"order_id"`
	Amount        int    `json:"amount"`
	Project       string `json:"project"`
	Status        string `json:"status"`
	PaymentMethod string `json:"payment_method"`
	CompletedAt   string `json:"completed_at"`
}

// Handler untuk Pakasir Webhook - menerima notifikasi pembayaran
func pakasirWebhookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	// Read request body
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("❌ Webhook: Failed to read body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read request body"})
		return
	}

	log.Printf("🔔 WEBHOOK RECEIVED: %s", string(bodyBytes))

	// Parse webhook payload
	var payload PakasirWebhookPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		log.Printf("❌ Webhook: Failed to parse body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid payload"})
		return
	}

	log.Printf("💰 PAYMENT WEBHOOK:")
	log.Printf("   Order ID: %s", payload.OrderID)
	log.Printf("   Amount: %d", payload.Amount)
	log.Printf("   Status: %s", payload.Status)
	log.Printf("   Payment Method: %s", payload.PaymentMethod)
	log.Printf("   Completed At: %s", payload.CompletedAt)

	// Simpan status pembayaran ke memory
	paymentMutex.Lock()
	paymentStatuses[payload.OrderID] = &PaymentStatus{
		OrderID:       payload.OrderID,
		Status:        payload.Status,
		Amount:        payload.Amount,
		PaymentMethod: payload.PaymentMethod,
		CompletedAt:   payload.CompletedAt,
		ReceivedAt:    time.Now(),
	}
	paymentMutex.Unlock()
	log.Printf("💾 Payment status saved to memory for order: %s", payload.OrderID)

	// Update Firestore via Vercel API (optional, untuk backup)
	if payload.Status == "completed" || payload.Status == "success" || payload.Status == "paid" {
		log.Printf("✅ PAYMENT COMPLETED for order: %s", payload.OrderID)
		go updateOrderPaymentStatus(payload)
	}

	// Return success response ke Pakasir
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"message":  "Webhook received",
		"order_id": payload.OrderID,
		"status":   payload.Status,
	})
}

// updateOrderPaymentStatus - call Vercel API to update Firestore
func updateOrderPaymentStatus(payload PakasirWebhookPayload) {
	// Vercel API URL - sesuaikan dengan deployment URL kamu
	vercelURL := os.Getenv("VERCEL_API_URL")
	if vercelURL == "" {
		// If not set, leave empty and fall back to common local hosts below
		vercelURL = ""
	}

	// Candidate endpoints to try (in order)
	candidates := []string{}
	if vercelURL != "" {
		candidates = append(candidates, strings.TrimRight(vercelURL, "/")+"/api/update-payment-status")
	}
	// Common local fallbacks
	candidates = append(candidates, "http://localhost:3000/api/update-payment-status")
	candidates = append(candidates, "http://localhost:5173/api/update-payment-status")

	// Prepare request body
	requestBody, err := json.Marshal(map[string]interface{}{
		"order_id":       payload.OrderID,
		"amount":         payload.Amount,
		"status":         payload.Status,
		"payment_method": payload.PaymentMethod,
		"completed_at":   payload.CompletedAt,
	})
	if err != nil {
		log.Printf("❌ Failed to marshal update request: %v", err)
		return
	}
	// Try each candidate until one succeeds
	client := &http.Client{Timeout: 30 * time.Second}
	for _, apiEndpoint := range candidates {
		log.Printf("📤 Trying update endpoint: %s", apiEndpoint)
		req, err := http.NewRequest("POST", apiEndpoint, bytes.NewBuffer(requestBody))
		if err != nil {
			log.Printf("❌ Failed to create request for %s: %v", apiEndpoint, err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("❌ Failed to call %s: %v", apiEndpoint, err)
			continue
		}

		respBody, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		log.Printf("📥 Response from %s [%d]: %s", apiEndpoint, resp.StatusCode, string(respBody))

		if resp.StatusCode == http.StatusOK {
			log.Printf("✅ Firestore updated successfully for order: %s via %s", payload.OrderID, apiEndpoint)
			return
		}

		log.Printf("⚠️ Endpoint %s returned status: %d - trying next candidate if any", apiEndpoint, resp.StatusCode)
	}

	log.Printf("❌ All update endpoints failed for order: %s", payload.OrderID)
}

// Handler untuk cek status pembayaran
func checkPaymentStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	orderID := r.URL.Query().Get("order_id")
	if orderID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "order_id is required"})
		return
	}

	paymentMutex.RLock()
	status, exists := paymentStatuses[orderID]
	paymentMutex.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"order_id": orderID,
			"found":    false,
			"status":   "pending",
			"message":  "No payment webhook received yet",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        true,
		"order_id":       orderID,
		"found":          true,
		"status":         status.Status,
		"amount":         status.Amount,
		"payment_method": status.PaymentMethod,
		"completed_at":   status.CompletedAt,
		"received_at":    status.ReceivedAt.Format(time.RFC3339),
	})
}

func main() {
	// Load .env dari root project
	// Di Railway: env var sudah di-set di dashboard, Load() gagal tapi tidak masalah
	// Di local: baca dari .env di root project (tempat go run dijalankan)
	godotenv.Load(".env")    // root project
	godotenv.Load("../.env") // fallback jika dijalankan dari subfolder

	zoneID := os.Getenv("ZONE_ID")
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	readAllToken := os.Getenv("CF_READ_ALL_TOKEN")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Clean startup banner
	fmt.Println()
	fmt.Println("  ☁️  Cloudflare Analytics Server v4.0.0")
	fmt.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  🌐 http://localhost:%s\n", port)
	fmt.Println()

	// Status indicators
	if zoneID != "" {
		fmt.Printf("  ✓ Zone ID configured\n")
	} else {
		fmt.Printf("  ✗ Zone ID missing\n")
	}
	if apiToken != "" {
		fmt.Printf("  ✓ Analytics API ready\n")
	} else {
		fmt.Printf("  ✗ Analytics API token missing\n")
	}
	if readAllToken != "" {
		fmt.Printf("  ✓ CF Read All token ready\n")
	} else {
		fmt.Printf("  ✗ CF_READ_ALL_TOKEN missing di .env root project\n")
	}

	fmt.Println()
	fmt.Println("  📡 Endpoints:")
	fmt.Println("     /api/cloudflare-analytics")
	fmt.Println("     /api/cf/verify")
	fmt.Println("     /api/cf/accounts")
	fmt.Println("     /api/cf/zones")
	fmt.Println("     /api/cf/dns?zone_id=xxx")
	fmt.Println("     /api/cf/firewall?zone_id=xxx")
	fmt.Println("     /api/cf/pagerules?zone_id=xxx")
	fmt.Println("     /api/cf/ssl?zone_id=xxx")
	fmt.Println("     /api/pakasir-create-transaction")
	fmt.Println("     /api/pakasir-webhook")
	fmt.Println("     /api/webhook/pakasir          <- Webhook URL untuk Pakasir (ngrok)")
	fmt.Println("     /api/check-payment-status     <- Polling endpoint untuk frontend")
	fmt.Println("     /api/health")
	fmt.Println()
	fmt.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  🚀 Server ready!")
	fmt.Println()

	// Setup routes dengan CORS middleware
	http.HandleFunc("/api/cloudflare-analytics", corsMiddleware(cloudflareHandler))
	// CF Overview proxy routes (Read All Resources)
	http.HandleFunc("/api/cf/verify", corsMiddleware(cfVerifyTokenHandler))
	http.HandleFunc("/api/cf/accounts", corsMiddleware(cfAccountsHandler))
	http.HandleFunc("/api/cf/zones", corsMiddleware(cfZonesHandler))
	http.HandleFunc("/api/cf/dns", corsMiddleware(cfDNSHandler))
	http.HandleFunc("/api/cf/firewall", corsMiddleware(cfFirewallHandler))
	http.HandleFunc("/api/cf/pagerules", corsMiddleware(cfPageRulesHandler))
	http.HandleFunc("/api/cf/ssl", corsMiddleware(cfSSLHandler))
	http.HandleFunc("/api/cf/waf", corsMiddleware(cfWAFHandler))
	// Pakasir & Webhook
	http.HandleFunc("/api/pakasir-create-transaction", corsMiddleware(pakasirHandler))
	http.HandleFunc("/api/pakasir-webhook", corsMiddleware(pakasirWebhookHandler))
	http.HandleFunc("/api/webhook/pakasir", corsMiddleware(pakasirWebhookHandler))
	http.HandleFunc("/api/check-payment-status", corsMiddleware(checkPaymentStatusHandler))
	http.HandleFunc("/api/health", corsMiddleware(healthHandler))
	http.HandleFunc("/api/test", corsMiddleware(testHandler))
	http.HandleFunc("/api/cf/debug", corsMiddleware(cfDebugHandler))

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("❌ Server failed:", err)
	}
}
