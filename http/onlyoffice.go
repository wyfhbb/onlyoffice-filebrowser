package http

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/allegro/bigcache"
	"github.com/filebrowser/filebrowser/v2/files"
	"github.com/golang-jwt/jwt/v4"
)

const (
	onlyOfficeStatusReadyForSaving              = 2
	onlyOfficeStatusEditingButCurrentStateSaved = 6
)

var (
	// Refer to only-office documentation on co-editing
	// https://api.onlyoffice.com/editors/coedit
	//
	// a 48 hour TTL here is not required, because the document server will notify
	// us when keys should be evicted. However, it is added defensively in order to
	// prevent potential memory leaks.
	coeditingDocumentKeys, _ = bigcache.NewBigCache(bigcache.DefaultConfig(48 * time.Hour))
)

type OnlyOfficeCallback struct {
	ChangesURL string   `json:"changesurl,omitempty"`
	Key        string   `json:"key,omitempty"`
	Status     int      `json:"status,omitempty"`
	URL        string   `json:"url,omitempty"`
	Users      []string `json:"users,omitempty"`
	UserData   string   `json:"userdata,omitempty"`
}

var onlyofficeClientConfigGetHandler = withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if d.settings.OnlyOffice.JWTSecret == "" {
		return http.StatusInternalServerError, errors.New("only-office integration must be configured in settings")
	}

	if !d.user.Perm.Modify || !d.Check(r.URL.Path) {
		return http.StatusForbidden, nil
	}

	referrer, err := getReferer(r)
	if err != nil {
		return http.StatusInternalServerError, errors.Join(errors.New("could not determine request referrer"), err)
	}

	file, err := files.NewFileInfo(files.FileOptions{
		Fs:         d.user.Fs,
		Path:       r.URL.Path,
		Modify:     d.user.Perm.Modify,
		Expand:     false,
		ReadHeader: d.server.TypeDetectionByHeader,
		Checker:    d,
	})

	if err != nil {
		return errToStatus(err), err
	}

	clientConfig := map[string]interface{}{
		"document": map[string]interface{}{
			"fileType": file.Extension[1:],
			"key":      getDocumentKey(file.RealPath()),
			"title":    file.Name,
			"url": (&url.URL{
				Scheme:   referrer.Scheme,
				Host:     referrer.Host,
				RawQuery: "auth=" + url.QueryEscape(d.authToken),
			}).JoinPath(d.server.BaseURL, "/api/raw", file.Path).String(),
			"permissions": map[string]interface{}{
				"edit":     d.user.Perm.Modify,
				"download": d.user.Perm.Download,
				"print":    d.user.Perm.Download,
			},
		},
		"editorConfig": map[string]interface{}{
			"callbackUrl": (&url.URL{
				Scheme:   referrer.Scheme,
				Host:     referrer.Host,
				RawQuery: "auth=" + url.QueryEscape(d.authToken) + "&save=" + url.QueryEscape(file.Path),
			}).JoinPath(d.server.BaseURL, "/api/onlyoffice/callback").String(),
			"user": map[string]interface{}{
				"id":   strconv.FormatUint(uint64(d.user.ID), 10),
				"name": d.user.Username,
			},
			"customization": map[string]interface{}{
				"autosave":  true,
				"forcesave": true,
				"uiTheme":   ternary(d.Settings.Branding.Theme == "dark", "default-dark", "default-light"),
			},
			"lang": d.user.Locale,
			"mode": ternary(d.user.Perm.Modify, "edit", "view"),
		},
		"type": ternary(r.URL.Query().Get("isMobile") == "true", "mobile", "desktop"),
	}

	signature, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(clientConfig)).SignedString([]byte(d.Settings.OnlyOffice.JWTSecret))
	if err != nil {
		return http.StatusInternalServerError, errors.Join(errors.New("could not sign only-office client-config"), err)
	}
	clientConfig["token"] = signature

	return renderJSON(w, r, clientConfig)
})

var onlyofficeCallbackHandler = withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	var data OnlyOfficeCallback
	err = json.Unmarshal(body, &data)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	if data.Status == onlyOfficeStatusReadyForSaving || data.Status == onlyOfficeStatusEditingButCurrentStateSaved {
		docPath := r.URL.Query().Get("save")
		if docPath == "" {
			return http.StatusInternalServerError, errors.New("unable to get file save path")
		}

		if data.Status == onlyOfficeStatusReadyForSaving {
			// Refer to only-office documentation on co-editing
			// https://api.onlyoffice.com/editors/coedit
			//
			// On this status, the document key should no longer be re-used.
			realPath := files.GetRealPath(d.user.Fs, docPath)
			coeditingDocumentKeys.Delete(realPath)
		}

		if !d.user.Perm.Modify || !d.Check(docPath) {
			return http.StatusForbidden, nil
		}

		doc, err := http.Get(data.URL)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		defer doc.Body.Close()

		err = d.Runner.RunHook(func() error {
			_, writeErr := writeFile(d.user.Fs, docPath, doc.Body)
			if writeErr != nil {
				return writeErr
			}
			return nil
		}, "save", docPath, "", d.user)

		if err != nil {
			return http.StatusInternalServerError, err
		}
	}

	resp := map[string]int{
		"error": 0,
	}
	return renderJSON(w, r, resp)
})

func getReferer(r *http.Request) (*url.URL, error) {
	if len(r.Header["Referer"]) != 1 {
		return nil, errors.New("expected exactly one Referer header")
	}

	return url.ParseRequestURI(r.Header["Referer"][0])
}

func getDocumentKey(realPath string) string {
	cachedDocumentKey, err := coeditingDocumentKeys.Get(realPath)
	if err != nil {
		// error is intentionally ignored in order treat errors
		// the same as a cache-miss
	}

	if cachedDocumentKey != nil {
		return string(cachedDocumentKey)
	} else {
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		documentKey := hashSHA256(realPath + timestamp)
		coeditingDocumentKeys.Set(realPath, []byte(documentKey))
		return documentKey
	}
}

func hashSHA256(data string) string {
	bytes := sha256.Sum256([]byte(data))
	return hex.EncodeToString(bytes[:])
}

func ternary(condition bool, trueValue string, falseValue string) string {
	if condition {
		return trueValue
	}
	return falseValue
}
