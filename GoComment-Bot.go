package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/patrickmn/go-cache"
)

func newGoComment() (*GoComment, error) {
	//读取配置文件
	confBytes, err := ioutil.ReadFile("./GoComment-Bot.json")
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	//初始化对象
	gc := new(GoComment)
	err = json.Unmarshal(confBytes, gc)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	//读取私钥
	pemBytes, err := ioutil.ReadFile(gc.PemPath)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	//初始化私钥
	gc.privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(pemBytes)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	//初始化jwtToken
	claims := new(jwt.StandardClaims)
	now := time.Now()
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(time.Minute * time.Duration(8)).Unix()
	claims.Issuer = gc.AppId
	gc.jwtToken = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	gc.bearer, err = gc.jwtToken.SignedString(gc.privateKey)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	//初始化缓存
	gc.botTokenCache = cache.New(55*time.Minute, 10*time.Minute)
	gc.validCache = cache.New(time.Hour, 10*time.Minute)
	gc.oauthCache = cache.New(time.Hour, 10*time.Minute)
	gc.issueCache = cache.New(time.Hour, 10*time.Minute)
	log.Println("Go Comment Bot running")
	return gc, nil
}

type BotToken struct {
	Token   string `json:"token,omitempty"`
	Expires string `json:"expries_at,omitempty"`
	Error   string `json:"error,omitempty"`
	Valid   bool
}

type UserToken struct {
	Token string `json:"access_token,omitempty"`
	Type  string `json:"token_type,omitempty"`
	Scope string `json:"scope,omitempty"`
	Error string `json:"error,omitempty"`
	Valid bool
}

type Issue struct {
	InstallationId string `json:"installation_id,omitempty"`
	Owner          string `json:"owner,omitempty"`
	Repo           string `json:"repo,omitempty"`
	UserToken      string `json:"access_token,omitempty"`
	Title          string `json:"title,omitempty"`
	Body           string `json:"body,omitempty"`
	Pid            string `json:"pid,omitempty"`
	IssueUrl       string `json:"html_url,omitempty"`
	CommentsUrl    string `json:"comments_url,omitempty"`
}

type AuthData struct {
	Code         string `json:"code"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type GoComment struct {
	ClientId      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	AppId         string `json:"app_id"`
	PemPath       string `json:"pem_path"`
	Port          int    `json:"port"`
	privateKey    *rsa.PrivateKey
	botTokenCache *cache.Cache
	validCache    *cache.Cache
	oauthCache    *cache.Cache
	issueCache    *cache.Cache
	jwtToken      *jwt.Token
	bearer        string
}

func (gc *GoComment) checkUserToken(userToken string) bool {
	if userToken == "" {
		return false
	}
	result := false
	cacheResult, found := gc.validCache.Get(userToken)
	if !found {
		apiUrl := "https://api.github.com/applications/" + gc.ClientId + "/tokens/" + userToken
		request, err := http.NewRequest("GET", apiUrl, nil)
		request.SetBasicAuth(gc.ClientId, gc.ClientSecret)
		client := &http.Client{}
		response, err := client.Do(request)
		if err != nil {
			log.Println(err)
			return false
		}
		if response.StatusCode == 200 {
			result = true
		} else {
			log.Println("CheckUserToken: " + response.Status)
			resultBytes, _ := ioutil.ReadAll(response.Body)
			log.Println(string(resultBytes))
			result = false
		}
		gc.validCache.Set(userToken, result, cache.DefaultExpiration)
	} else {
		result = cacheResult.(bool)
	}
	return result
}

func (gc *GoComment) getBotToken(installationId string) (*BotToken, error) {
	var botToken *BotToken
	botTokenCache, found := gc.botTokenCache.Get(installationId)
	if !found {
		if gc.jwtToken.Claims.Valid() == nil {
			claims := new(jwt.StandardClaims)
			now := time.Now()
			claims.IssuedAt = now.Unix()
			claims.ExpiresAt = now.Add(time.Minute * time.Duration(8)).Unix()
			claims.Issuer = gc.AppId
			gc.jwtToken.Claims = claims
			bearer, err := gc.jwtToken.SignedString(gc.privateKey)
			if err != nil {
				return nil, err
			}
			gc.bearer = bearer
		}
		apiUrl := "https://api.github.com/app/installations/" + installationId + "/access_tokens"
		headers := make(map[string]string)
		headers["Authorization"] = "Bearer " + gc.bearer
		headers["Accept"] = "application/vnd.github.machine-man-preview+json"
		botToken = new(BotToken)
		err := httpPost(apiUrl, headers, nil, botToken)
		if err != nil {
			log.Println("getBotToken error: " + err.Error())
			botToken.Error = err.Error()
			gc.botTokenCache.Set(installationId, botToken, time.Minute)
			return nil, err
		}
		botToken.Valid = true
		gc.botTokenCache.Set(installationId, botToken, cache.DefaultExpiration)
	} else {
		botToken = botTokenCache.(*BotToken)
	}
	if !botToken.Valid {
		return nil, errors.New(botToken.Error)
	}
	return botToken, nil
}

func (gc *GoComment) Issue(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")             //允许访问所有域
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type") //header的类型
	w.Header().Set("content-type", "application/json")             //返回数据格式是json
	//读取请求内容
	bodyByte, err := ioutil.ReadAll(io.LimitReader(req.Body, 1048576))
	log.Println("Issue: " + string(bodyByte))
	if err != nil {
		log.Println(err.Error())
		json.NewEncoder(w).Encode(err)
		return
	}

	//转换为issue
	issue := new(Issue)
	err = json.Unmarshal(bodyByte, issue)
	if err != nil {
		log.Println(err)
		json.NewEncoder(w).Encode(err)
		return
	}

	//计算 issue key
	keyBytes := []byte(issue.Owner + "/" + issue.Repo + "/" + issue.Pid)
	key := fmt.Sprintf("%x", md5.Sum(keyBytes))

	//防止重复提交
	_, found := gc.issueCache.Get(key)
	if found {
		log.Println(err)
		json.NewEncoder(w).Encode(errors.New("issue duplicate"))
		return
	} else {
		gc.issueCache.Set(key, key, cache.DefaultExpiration)
	}

	//检查 user token
	if !gc.checkUserToken(issue.UserToken) {
		log.Println("Invalid token")
		json.NewEncoder(w).Encode("Invalid token")
		return
	}
	//获取 bot token
	botToken, err := gc.getBotToken(issue.InstallationId)
	if err != nil {
		log.Println(err)
		json.NewEncoder(w).Encode(err)
		return
	}

	//新建issue
	issue.Body = issue.Body + "\n---\n`" + key + "`"
	apiUrl := "https://api.github.com/repos/" + issue.Owner + "/" + issue.Repo + "/issues"
	headers := make(map[string]string)
	headers["Authorization"] = "token " + botToken.Token
	headers["Accept"] = "application/vnd.github.machine-man-preview+json"
	result := new(Issue)
	err = httpPost(apiUrl, headers, issue, result)
	if err != nil {
		gc.issueCache.Delete(key)
		log.Println(err)
		json.NewEncoder(w).Encode(err)
		return
	}
	json.NewEncoder(w).Encode(result)
}

func (gc *GoComment) OAuth(w http.ResponseWriter, req *http.Request) {
	//检查重定向url
	encodeUrl := req.FormValue("url")
	if encodeUrl == "" {
		log.Println("url is null")
		io.WriteString(w, "url is null")
		return
	}
	decodedUrl, err := base64.StdEncoding.DecodeString(encodeUrl)
	if err != nil {
		log.Println(err)
		io.WriteString(w, err.Error())
		return
	}
	redirectUrl, err := url.Parse(string(decodedUrl))
	if err != nil {
		log.Println(err)
		io.WriteString(w, err.Error())
		return
	}
	//检查code
	code := req.FormValue("code")
	if code == "" {
		log.Println("code is null")
		io.WriteString(w, "code is null")
		return
	}
	log.Println("code:" + code)
	var userToken *UserToken

	//读取 user token 缓存
	userTokenCache, found := gc.oauthCache.Get(code)
	if !found {
		oauthUrl := "https://github.com/login/oauth/access_token"
		data := new(AuthData)
		data.Code = code
		data.ClientId = gc.ClientId
		data.ClientSecret = gc.ClientSecret
		headers := make(map[string]string)
		headers["Accept"] = "application/json"
		userToken = new(UserToken)
		err = httpPost(oauthUrl, headers, data, userToken)
		if err != nil {
			userToken.Error = err.Error()
		}
		if userToken.Error != "" {
			gc.oauthCache.Set(code, userToken, cache.DefaultExpiration)
			log.Println("oauth error: " + userToken.Error)
			io.WriteString(w, "oauth error: "+userToken.Error)
			return
		}
		userToken.Valid = true
		gc.oauthCache.Set(code, userToken, cache.DefaultExpiration)
	} else {
		userToken = userTokenCache.(*UserToken)
	}
	if !userToken.Valid {
		log.Println("oauth error: " + userToken.Error)
		io.WriteString(w, "oauth error: "+userToken.Error)
		return
	}
	log.Println("token:" + userToken.Token)
	query := redirectUrl.Query()
	query.Add("access_token", userToken.Token)
	redirectUrl.RawQuery = query.Encode()
	http.Redirect(w, req, redirectUrl.String(), 302)
}

func httpPost(url string, headers map[string]string, data interface{}, result interface{}) error {
	var postData io.Reader
	if data != nil {
		dataBytes, err := json.Marshal(data)
		if err != nil {
			log.Println("httpPost:" + err.Error())
			return err
		}
		postData = bytes.NewBuffer(dataBytes)
	}
	request, err := http.NewRequest("POST", url, postData)
	if err != nil {
		log.Println(err)
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Println(err)
		return err
	}
	defer response.Body.Close()
	resultBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return errors.New(string(resultBytes))
	}
	log.Println("httpPost result:" + string(resultBytes))
	return json.Unmarshal(resultBytes, result)
}

func main() {
	gc, err := newGoComment()
	if err != nil {
		log.Fatal(err)
		return
	}
	http.HandleFunc("/oauth", gc.OAuth)
	http.HandleFunc("/issue", gc.Issue)
	http.ListenAndServe(":"+strconv.Itoa(gc.Port), nil)
}
