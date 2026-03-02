package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	gomail "gopkg.in/gomail.v2"
)


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

type PakasirWebhookPayload struct {
	OrderID       string `json:"order_id"`
	Amount        int    `json:"amount"`
	Project       string `json:"project"`
	Status        string `json:"status"`
	PaymentMethod string `json:"payment_method"`
	CompletedAt   string `json:"completed_at"`
}


type UploadResult struct {
	Success bool
	URL     string
	Error   string
}

type ApplicationFileURLs struct {
	CvURL          string `json:"cvUrl"`
	PhotoURL       string `json:"photoUrl"`
	KtpURL         string `json:"ktpUrl"`
	CertificateURL string `json:"certificateUrl"`
}


func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

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


func cloudflareHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	zoneID := os.Getenv("ZONE_ID")
	token := r.Header.Get("X-Cloudflare-Token")
	if token == "" {
		token = os.Getenv("CLOUDFLARE_API_TOKEN")
	}

	log.Printf("🔍 Fetching analytics for zone: %s", zoneID)

	if zoneID == "" || token == "" {
		log.Printf("❌ Missing credentials")
		json.NewEncoder(w).Encode(CloudflareResponse{
			Status: "error",
			Error:  "ZONE_ID atau CLOUDFLARE_API_TOKEN belum diatur di .env file",
		})
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
        dimensions { date }
        sum { bytes cachedBytes cachedRequests requests threats }
        uniq { uniques }
      }
    }
  }
}`

	now := time.Now().UTC()
	sevenDaysAgo := now.AddDate(0, 0, -7)

	payload := GraphQLRequest{
		Query: query,
		Variables: map[string]interface{}{
			"zoneTag":       zoneID,
			"datetimeStart": sevenDaysAgo.Format("2006-01-02"),
			"datetimeEnd":   now.Format("2006-01-02"),
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(CloudflareResponse{Status: "error", Error: err.Error()})
		return
	}

	req, err := http.NewRequest("POST", "https://api.cloudflare.com/client/v4/graphql", bytes.NewBuffer(payloadBytes))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(CloudflareResponse{Status: "error", Error: err.Error()})
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(CloudflareResponse{Status: "error", Error: err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(CloudflareResponse{Status: "error", Error: "Response bukan JSON valid"})
		return
	}

	if errors, ok := result["errors"].([]interface{}); ok && len(errors) > 0 {
		errorMsg := "Unknown error from Cloudflare"
		if errObj, ok := errors[0].(map[string]interface{}); ok {
			if msg, ok := errObj["message"].(string); ok {
				errorMsg = msg
			}
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CloudflareResponse{Status: "error", Error: errorMsg})
		return
	}

	log.Printf("✅ Analytics fetched for zone: %s", zoneID)
	json.NewEncoder(w).Encode(CloudflareResponse{Status: "success", Data: result, Zone: zoneID})
}


func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"service":   "feelin-coffee-server",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "5.0.0",
	})
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	zoneID := os.Getenv("ZONE_ID")
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	readAllToken := os.Getenv("CF_READ_ALL_TOKEN")

	maskToken := func(t string) string {
		if t == "" || len(t) <= 8 {
			return t
		}
		return t[:4] + "..." + t[len(t)-4:]
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"service":              "Feelin Coffee Server",
		"status":               "running",
		"zone_id":              zoneID,
		"has_api_token":        apiToken != "",
		"api_token_masked":     maskToken(apiToken),
		"has_readall_token":    readAllToken != "",
		"readall_token_masked": maskToken(readAllToken),
		"timestamp":            time.Now().Format(time.RFC3339),
		"endpoints": map[string]string{
			"analytics":          "/api/cloudflare-analytics",
			"submit_application": "/api/submit-application",
			"health":             "/api/health",
		},
	})
}

func cfDebugHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	maskToken := func(t string) string {
		if t == "" {
			return "❌ KOSONG / TIDAK TERBACA"
		}
		if len(t) <= 8 {
			return "✅ ADA (terlalu pendek)"
		}
		return "✅ ADA → " + t[:4] + "****" + t[len(t)-4:]
	}

	cfToken := os.Getenv("CF_READ_ALL_TOKEN")
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
			"CF_READ_ALL_TOKEN":     maskToken(cfToken),
			"CLOUDFLARE_API_TOKEN":  maskToken(os.Getenv("CLOUDFLARE_API_TOKEN")),
			"ZONE_ID":               maskToken(os.Getenv("ZONE_ID")),
			"CLOUDINARY_CLOUD_NAME": maskToken(os.Getenv("CLOUDINARY_CLOUD_NAME")),
			"HR_EMAIL":              maskToken(os.Getenv("HR_EMAIL")),
		},
		"cloudflare_verify_test": verifyStatus,
	})


func getReadAllToken(r *http.Request) string {
	if t := r.Header.Get("X-CF-Read-Token"); t != "" {
		return t
	}
	return os.Getenv("CF_READ_ALL_TOKEN")
}

func cfGet(w http.ResponseWriter, token, apiPath string) {
	w.Header().Set("Content-Type", "application/json")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "CF_READ_ALL_TOKEN belum diatur"})
		return
	}
	req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4"+apiPath, nil)
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
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func cfVerifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	cfGet(w, getReadAllToken(r), "/user/tokens/verify")
}
func cfAccountsHandler(w http.ResponseWriter, r *http.Request) {
	cfGet(w, getReadAllToken(r), "/accounts?per_page=10")
}
func cfZonesHandler(w http.ResponseWriter, r *http.Request) {
	cfGet(w, getReadAllToken(r), "/zones?per_page=20")
}
func cfDNSHandler(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "zone_id wajib diisi"})
		return
	}
	cfGet(w, getReadAllToken(r), "/zones/"+zoneID+"/dns_records?per_page=50&order=type")
}
func cfFirewallHandler(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "zone_id wajib diisi"})
		return
	}
	cfGet(w, getReadAllToken(r), "/zones/"+zoneID+"/firewall/rules?per_page=20")
}
func cfPageRulesHandler(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "zone_id wajib diisi"})
		return
	}
	cfGet(w, getReadAllToken(r), "/zones/"+zoneID+"/pagerules?status=active&per_page=20")
}
func cfWAFHandler(w http.ResponseWriter, r *http.Request) {
	zoneID := r.URL.Query().Get("zone_id")
	if zoneID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "zone_id wajib diisi"})
		return
	}
	cfGet(w, getReadAllToken(r), "/zones/"+zoneID+"/rulesets?phase=http_request_firewall_custom")
}

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
		req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones/"+zoneID+"/settings/"+setting, nil)
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

func pakasirHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read request body"})
		return
	}

	var reqBody PakasirRequest
	if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	if reqBody.OrderID == "" || reqBody.Amount <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "order_id dan amount wajib diisi"})
		return
	}

	paymentMethod := reqBody.PaymentMethod
	if paymentMethod == "" {
		paymentMethod = "qris"
	}

	pakasirProject := os.Getenv("PAKASIR_PROJECT")
	if pakasirProject == "" {
		pakasirProject = "feelin"
	}
	pakasirApiKey := os.Getenv("PAKASIR_API_KEY")
	if pakasirApiKey == "" {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Server misconfiguration"})
		return
	}

	pakasirReq := map[string]interface{}{
		"project":  pakasirProject,
		"order_id": reqBody.OrderID,
		"amount":   reqBody.Amount,
		"api_key":  pakasirApiKey,
	}

	payloadBytes, _ := json.Marshal(pakasirReq)
	pakasirURL := fmt.Sprintf("https://app.pakasir.com/api/transactioncreate/%s", paymentMethod)

	req, err := http.NewRequest("POST", pakasirURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to connect to Pakasir API"})
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("✅ Pakasir response [%d]: %s", resp.StatusCode, string(body))
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func pakasirWebhookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read request body"})
		return
	}

	log.Printf("🔔 WEBHOOK RECEIVED: %s", string(bodyBytes))

	var payload PakasirWebhookPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid payload"})
		return
	}

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

	if payload.Status == "completed" || payload.Status == "success" || payload.Status == "paid" {
		go updateOrderPaymentStatus(payload)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"message":  "Webhook received",
		"order_id": payload.OrderID,
		"status":   payload.Status,
	})
}

func updateOrderPaymentStatus(payload PakasirWebhookPayload) {
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "https://www.feelin.my.id"
	}

	candidates := []string{
		strings.TrimRight(frontendURL, "/") + "/api/update-payment-status",
		"https://www.feelin.my.id/api/update-payment-status",
	}

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

	client := &http.Client{Timeout: 30 * time.Second}
	for _, endpoint := range candidates {
		req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(requestBody))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			log.Printf("✅ Firestore updated for order: %s", payload.OrderID)
			return
		}
	}
	log.Printf("❌ All update endpoints failed for order: %s", payload.OrderID)
}

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
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"order_id": orderID,
			"found":    false,
			"status":   "pending",
			"message":  "No payment webhook received yet",
		})
		return
	}

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



// submit apk buat email 
func uploadToCloudinary(fileBytes []byte, filename, label string) UploadResult {
	cloudName := os.Getenv("CLOUDINARY_CLOUD_NAME")
	uploadPreset := os.Getenv("CLOUDINARY_UPLOAD_PRESET")
	if cloudName == "" {
		cloudName = "diljtaox1"
	}
	if uploadPreset == "" {
		uploadPreset = "feelin_coffee_recruitment"
	}

	log.Printf("☁️  [Cloudinary] %s: %s", label, filename)

	ext := ""
	if idx := strings.LastIndex(filename, "."); idx >= 0 {
		ext = strings.ToLower(filename[idx+1:])
	}
	resourceType := "image"
	if ext == "pdf" || ext == "doc" || ext == "docx" {
		resourceType = "raw"
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writer.WriteField("upload_preset", uploadPreset)
	writer.WriteField("folder", "feelin-coffee-recruitment")

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return UploadResult{Error: "CreateFormFile error: " + err.Error()}
	}
	part.Write(fileBytes)
	writer.Close()

	uploadURL := fmt.Sprintf("https://api.cloudinary.com/v1_1/%s/%s/upload", cloudName, resourceType)
	log.Printf("☁️  [Cloudinary] URL: %s (resource_type=%s)", uploadURL, resourceType)

	req, err := http.NewRequest("POST", uploadURL, &body)
	if err != nil {
		return UploadResult{Error: "NewRequest error: " + err.Error()}
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return UploadResult{Error: "Cloudinary network error: " + err.Error()}
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)
	log.Printf(" [Cloudinary] Response HTTP %d: %s", resp.StatusCode, string(respBody))

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	if secureURL, ok := result["secure_url"].(string); ok && secureURL != "" {
		log.Printf(" [Cloudinary] %s → %s", label, secureURL)
		return UploadResult{Success: true, URL: secureURL}
	}

	errMsg := fmt.Sprintf("Cloudinary HTTP %d", resp.StatusCode)
	if errObj, ok := result["error"].(map[string]interface{}); ok {
		if msg, ok := errObj["message"].(string); ok {
			errMsg = "Cloudinary: " + msg
		}
	}
	log.Printf("❌ [Cloudinary] %s gagal: %s", label, errMsg)
	return UploadResult{Error: errMsg}
}

func uploadToLitterbox(fileBytes []byte, filename, label string) UploadResult {
	log.Printf("[Litterbox] %s: %s", label, filename)

	doUpload := func(apiURL, timeParam string) (string, error) {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		writer.WriteField("reqtype", "fileupload")
		if timeParam != "" {
			writer.WriteField("time", timeParam)
		}
		part, err := writer.CreateFormFile("fileToUpload", filename)
		if err != nil {
			return "", err
		}
		part.Write(fileBytes)
		writer.Close()

		req, _ := http.NewRequest("POST", apiURL, &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		respBytes, _ := ioutil.ReadAll(resp.Body)
		url := strings.TrimSpace(string(respBytes))
		if strings.HasPrefix(url, "https://") {
			return url, nil
		}
		return "", fmt.Errorf("invalid response: %s", url)
	}

	url, err := doUpload("https://litterbox.catbox.moe/resources/internals/api.php", "72h")
	if err == nil {
		log.Printf(" [Litterbox] %s → %s", label, url)
		return UploadResult{Success: true, URL: url}
	}
	log.Printf("⚠️  Litterbox gagal (%s), fallback Catbox...", err.Error())

	// Fallback Catbox (permanen)
	url, err = doUpload("https://catbox.moe/user/api.php", "")
	if err == nil {
		log.Printf(" [Catbox] %s → %s", label, url)
		return UploadResult{Success: true, URL: url}
	}

	return UploadResult{Error: "Litterbox & Catbox gagal: " + err.Error()}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func sendEmailToHR(fields map[string]string, urls ApplicationFileURLs) error {
	smtpHost := os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		smtpHost = "smtp.gmail.com"
	}
	smtpPortStr := os.Getenv("SMTP_PORT")
	if smtpPortStr == "" {
		smtpPortStr = "587"
	}
	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		return fmt.Errorf("SMTP_PORT tidak valid: %v", err)
	}
	smtpUser := os.Getenv("SMTP_USER")
	if smtpUser == "" {
		smtpUser = "hudzaifaharantisi17@gmail.com"
	}
	smtpPass := os.Getenv("SMTP_PASS")
	if smtpPass == "" {
		return fmt.Errorf("SMTP_PASS belum diatur – set Google App Password di environment variables")
	}
	hrEmail := os.Getenv("HR_EMAIL")
	if hrEmail == "" {
		hrEmail = "hudzaifaharantisi17@gmail.com"
	}

	row := func(label, value string) string {
		v := orDefault(value, "Tidak ada")
		return fmt.Sprintf(`<tr><td style="padding:8px 12px;border:1px solid #ddd;font-weight:bold;background:#f9f9f9;">%s</td><td style="padding:8px 12px;border:1px solid #ddd;">%s</td></tr>`, label, v)
	}
	linkCell := func(label, url string) string {
		if url == "" {
			return row(label, "Tidak ada")
		}
		return fmt.Sprintf(`<tr><td style="padding:8px 12px;border:1px solid #ddd;font-weight:bold;background:#f9f9f9;">%s</td><td style="padding:8px 12px;border:1px solid #ddd;"><a href="%s" target="_blank">Lihat / Download</a></td></tr>`, label, url)
	}

	htmlBody := fmt.Sprintf(`
<html><body style="font-family:Arial,sans-serif;">
<h2 style="color:#4a2c2a;">📋 Lamaran Baru</h2>
<table style="border-collapse:collapse;width:100%%;max-width:600px;">
%s%s%s%s%s%s%s%s%s%s%s%s%s%s
</table>
<br><p style="color:#888;font-size:12px;">Email ini dikirim otomatis oleh sistem Feelin Coffee.</p>
</body></html>`,
		row("Posisi Dilamar", fields["position"]),
		row("Nama Lengkap", fields["fullName"]),
		row("Email Pelamar", fields["email"]),
		row("Telepon", fields["phone"]),
		row("Usia", orDefault(fields["age"], "Tidak ada")+" tahun"),
		row("Alamat", fields["address"]),
		row("Pendidikan Terakhir", fields["education"]),
		row("Pengalaman Kerja", fields["experience"]),
		row("Informasi Tambahan", orDefault(fields["additionalInfo"], "-")),
		row("Tanggal Melamar", time.Now().Format("02 January 2006 15:04")),
		linkCell("CV", urls.CvURL),
		linkCell("Foto", urls.PhotoURL),
		linkCell("KTP", urls.KtpURL),
		linkCell("Sertifikat", urls.CertificateURL),
	)

	m := gomail.NewMessage()
	m.SetHeader("From", smtpUser)
	m.SetHeader("To", hrEmail)
	m.SetHeader("Subject", fmt.Sprintf("📋 Lamaran Baru: %s - %s", fields["position"], fields["fullName"]))
	m.SetBody("text/html", htmlBody)

	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPass)

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("gagal kirim email via SMTP: %v", err)
	}
	return nil
}

func submitApplicationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	if err := r.ParseMultipartForm(20 << 20); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to parse form: " + err.Error()})
		return
	}

	fields := map[string]string{
		"position":       r.FormValue("position"),
		"fullName":       r.FormValue("fullName"),
		"email":          r.FormValue("email"),
		"phone":          r.FormValue("phone"),
		"age":            r.FormValue("age"),
		"address":        r.FormValue("address"),
		"education":      r.FormValue("education"),
		"experience":     r.FormValue("experience"),
		"additionalInfo": r.FormValue("additionalInfo"),
	}

	log.Printf("📨 Lamaran masuk: %s → %s", fields["fullName"], fields["position"])

	readFile := func(key string) ([]byte, string, bool) {
		file, header, err := r.FormFile(key)
		if err != nil {
			return nil, "", false
		}
		defer file.Close()
		data, err := ioutil.ReadAll(file)
		if err != nil {
			log.Printf("❌ readFile(%s) error: %v", key, err)
			return nil, "", false
		}
		log.Printf("📎 File diterima: %s → %s (%d bytes)", key, header.Filename, len(data))
		return data, header.Filename, true
	}

	type uploadJob struct {
		key    string
		result UploadResult
	}
	ch := make(chan uploadJob, 4)

	uploadAsync := func(key, linkKey string, useCloudinary bool) {
		if link := r.FormValue(linkKey); link != "" {
			log.Printf("🔗 %s: pakai link manual → %s", key, link)
			ch <- uploadJob{key, UploadResult{Success: true, URL: link}}
			return
		}
		data, filename, ok := readFile(key + "File")
		if !ok {
			log.Printf("ℹ️  %s: tidak ada file dan tidak ada link", key)
			ch <- uploadJob{key, UploadResult{}}
			return
		}
		if useCloudinary {
			ch <- uploadJob{key, uploadToCloudinary(data, filename, key)}
		} else {
			ch <- uploadJob{key, uploadToLitterbox(data, filename, key)}
		}
	}

	go uploadAsync("cv",    "cvLink",    false) // CV → Litterbox (PDF/DOC)
	go uploadAsync("photo", "photoLink", true)  // Foto → Cloudinary
	go uploadAsync("ktp",   "ktpLink",   true)  // KTP → Cloudinary

	go func() {
		if link := r.FormValue("certificateLink"); link != "" {
			log.Printf("🔗 certificate: pakai link manual → %s", link)
			ch <- uploadJob{"certificate", UploadResult{Success: true, URL: link}}
			return
		}
		data, filename, ok := readFile("certificateFile")
		if !ok {
			log.Printf("ℹ️  certificate: tidak ada file dan tidak ada link")
			ch <- uploadJob{"certificate", UploadResult{}}
			return
		}
		ext := ""
		if idx := strings.LastIndex(filename, "."); idx >= 0 {
			ext = strings.ToLower(filename[idx+1:])
		}
		if ext == "pdf" {
			ch <- uploadJob{"certificate", uploadToLitterbox(data, filename, "Sertifikat")}
		} else {
			ch <- uploadJob{"certificate", uploadToCloudinary(data, filename, "Sertifikat")}
		}
	}()

	urls := ApplicationFileURLs{}
	uploadErrors := []string{}

	for i := 0; i < 4; i++ {
		job := <-ch
		if job.result.Success {
			log.Printf(" Upload %s berhasil → %s", job.key, job.result.URL)
		} else if job.result.Error != "" {
			log.Printf(" Upload %s GAGAL: %s", job.key, job.result.Error)
			uploadErrors = append(uploadErrors, fmt.Sprintf("%s: %s", job.key, job.result.Error))
		} else {
			log.Printf("ℹ Upload %s: tidak ada file/link", job.key)
		}

		switch job.key {
		case "cv":
			urls.CvURL = job.result.URL
		case "photo":
			urls.PhotoURL = job.result.URL
		case "ktp":
			urls.KtpURL = job.result.URL
		case "certificate":
			urls.CertificateURL = job.result.URL
		}
	}

	log.Printf("📊 Final URLs → cv:%q photo:%q ktp:%q cert:%q",
		urls.CvURL, urls.PhotoURL, urls.KtpURL, urls.CertificateURL)

	emailSuccess := true
	if err := sendEmailToHR(fields, urls); err != nil {
		log.Printf("⚠️  Email HR gagal: %v", err)
		emailSuccess = false
	} else {
		log.Printf("✅ Email HR terkirim")
	}

	response := map[string]interface{}{
		"success":      true,
		"emailSuccess": emailSuccess,
		"fileUrls":     urls,
		"message":      "Lamaran berhasil diproses",
	}
	if len(uploadErrors) > 0 {
		response["uploadWarnings"] = uploadErrors
	}

	json.NewEncoder(w).Encode(response)
}


func main() {
	godotenv.Load(".env")
	godotenv.Load("../.env")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	zoneID := os.Getenv("ZONE_ID")
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	readAllToken := os.Getenv("CF_READ_ALL_TOKEN")
	cloudinaryName := os.Getenv("CLOUDINARY_CLOUD_NAME")

	fmt.Println()
	fmt.Println("  Feelin-server-Golang")
	fmt.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  🌐 http://localhost:%s\n\n", port)

	checkEnv := func(label, val string) {
		if val != "" {
			fmt.Printf("  ✓ %s\n", label)
		} else {
			fmt.Printf("  ✗ %s missing\n", label)
		}
	}
	checkEnv("Zone ID", zoneID)
	checkEnv("Cloudflare Analytics Token", apiToken)
	checkEnv("CF Read All Token", readAllToken)
	checkEnv("Cloudinary Cloud Name", cloudinaryName)

	fmt.Println()
	fmt.Println("  📡 Endpoints:")
	fmt.Println("     POST /api/submit-application   ← Lamaran kerja")
	fmt.Println("     GET  /api/cloudflare-analytics")
	fmt.Println("     GET  /api/cf/verify|accounts|zones|dns|firewall|pagerules|ssl|waf")
	fmt.Println("     POST /api/pakasir-create-transaction")
	fmt.Println("     POST /api/pakasir-webhook")
	fmt.Println("     GET  /api/check-payment-status")
	fmt.Println("     GET  /api/health | /api/test | /api/cf/debug")
	fmt.Println()
	fmt.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  🚀 Server ready!")
	fmt.Println()

	// Routes
	http.HandleFunc("/api/submit-application",        corsMiddleware(submitApplicationHandler))
	http.HandleFunc("/api/cloudflare-analytics",      corsMiddleware(cloudflareHandler))
	http.HandleFunc("/api/cf/verify",                 corsMiddleware(cfVerifyTokenHandler))
	http.HandleFunc("/api/cf/accounts",               corsMiddleware(cfAccountsHandler))
	http.HandleFunc("/api/cf/zones",                  corsMiddleware(cfZonesHandler))
	http.HandleFunc("/api/cf/dns",                    corsMiddleware(cfDNSHandler))
	http.HandleFunc("/api/cf/firewall",               corsMiddleware(cfFirewallHandler))
	http.HandleFunc("/api/cf/pagerules",              corsMiddleware(cfPageRulesHandler))
	http.HandleFunc("/api/cf/ssl",                    corsMiddleware(cfSSLHandler))
	http.HandleFunc("/api/cf/waf",                    corsMiddleware(cfWAFHandler))
	http.HandleFunc("/api/pakasir-create-transaction", corsMiddleware(pakasirHandler))
	http.HandleFunc("/api/pakasir-webhook",            corsMiddleware(pakasirWebhookHandler))
	http.HandleFunc("/api/webhook/pakasir",            corsMiddleware(pakasirWebhookHandler))
	http.HandleFunc("/api/check-payment-status",       corsMiddleware(checkPaymentStatusHandler))
	http.HandleFunc("/api/health",                     corsMiddleware(healthHandler))
	http.HandleFunc("/api/test",                       corsMiddleware(testHandler))
	http.HandleFunc("/api/cf/debug",                   corsMiddleware(cfDebugHandler))

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("❌ Server failed:", err)
	}
}
