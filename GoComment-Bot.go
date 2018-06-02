package main
 
import (
    "net/http"
    "encoding/base64"
    "encoding/json"
    "io/ioutil"
    "io"
    "bytes"
	"log"
	"strconv"
	"time"
	"crypto/rsa"

	"github.com/dgrijalva/jwt-go"
	"github.com/patrickmn/go-cache"
)

func newGoComment() (*GoComment,error){
	//读取配置文件
	confBytes, err := ioutil.ReadFile("./GoComment-Bot.conf")
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
    claims.ExpiresAt = now.Add(time.Minute * time.Duration(10)).Unix()
    claims.Issuer = gc.AppId
	gc.jwtToken = jwt.NewWithClaims(jwt.SigningMethodRS256,claims)
	gc.bearer, err = gc.jwtToken.SignedString(gc.privateKey)
	if err != nil {
	   log.Fatal(err)
       return nil, err	
	}
    //初始化缓存
    gc.tokenCache = cache.New(55*time.Minute, 10*time.Minute)
    return gc, nil
}

type BotToken struct{
	Token 			string `json:"token,omitempty"`
	Expires 		string `json:"expries_at,omitempty"`
	Error 			string `json:"error,omitempty"`
}

type UserToken struct{
	Token 			string `json:"access_token,omitempty"`
	Type 			string `json:"token_type,omitempty"`
	Scope 			string `json:"scope,omitempty"`
	Error 			string `json:"error,omitempty"`
}

type Issue struct{
	InstallationId 	string 	`json:"installation_id,omitempty"`
	Owner			string 	`json:"owner,omitempty"`
	Repo 			string 	`json:"repo,omitempty"`
	UserToken		string 	`json:"access_token,omitempty"`
	Title 			string 	`json:"title,omitempty"`
	Body 			string 	`json:"body,omitempty"`
	Comments_url 	string 	`json:"comments_url,omitempty"`
}

type AuthData struct{
	Code 			string `json:"code"`
	ClientId 		string `json:"client_id"`
	ClientSecret 	string `json:"client_secret"`
}

type GoComment struct{
	ClientId 		string `json:"client_id"`
	ClientSecret 	string `json:"client_secret"`
	AppId 			string `json:"app_id"`
	PemPath			string `json:"pem_path"`
	Port 			int	   `json:"port"`
	privateKey 		*rsa.PrivateKey
	tokenCache 		*cache.Cache
	jwtToken 		*jwt.Token
	bearer 			string
}

func (gc *GoComment) checkUserToken(userToken string) bool {
	if userToken == "" {
		return false
	}
	url := "https://api.github.com/applications/"+gc.ClientId+"/tokens/"+userToken
	request, err := http.NewRequest("GET", url, nil)
	request.SetBasicAuth(gc.ClientId, gc.ClientSecret)
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Println(err)
		return false
	}
	if response.StatusCode == 200 {
		return true
	}else{
		return false
	}

}

func (gc *GoComment) getBotToken(installationId string) (string, error) {
	var token string
	x, found := gc.tokenCache.Get(installationId)
	if !found {
		if gc.jwtToken.Claims.Valid() == nil {
		    claims := new(jwt.StandardClaims)
		    now := time.Now()
		    claims.IssuedAt = now.Unix()
		    claims.ExpiresAt = now.Add(time.Minute * time.Duration(10)).Unix()
		    claims.Issuer = gc.AppId
		    gc.jwtToken.Claims = claims
			bearer, err := gc.jwtToken.SignedString(gc.privateKey)
			if err != nil {
				log.Println(err)
				return "", err
			}
			gc.bearer = bearer
		}
		url := "https://api.github.com/app/installations/" + installationId + "/access_tokens"
		headers := make(map[string]string)
		headers["Authorization"] = "Bearer " + gc.bearer
		headers["Accept"] = "application/vnd.github.machine-man-preview+json"
		botToken := new(BotToken)
    	err := httpPost(url,headers,nil,botToken)
		if err != nil {
			log.Println(err)
			return "", err
		}
		gc.tokenCache.Set(installationId, botToken.Token, cache.DefaultExpiration)
		token = botToken.Token
	}else{
		token = x.(string)
	}
	return token, nil	
}

func (gc *GoComment) Issue(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")             //允许访问所有域
	w.Header().Add("Access-Control-Allow-Headers", "Content-Type") //header的类型
	w.Header().Set("content-type", "application/json")             //返回数据格式是json
	bodyByte, err := ioutil.ReadAll(io.LimitReader(req.Body, 1048576))
	log.Println("Issue: "+ string(bodyByte))
    if err != nil {
		log.Println(err.Error())
		io.WriteString(w, err.Error())
		return
	}
    if err := req.Body.Close(); err != nil {
        panic(err)
    }
	issue := new(Issue)
	err = json.Unmarshal(bodyByte, issue)
	if err != nil {
		log.Println(err)
		io.WriteString(w, err.Error())
		return
	}
	if !gc.checkUserToken(issue.UserToken) {
		log.Println("Invalid token")
		io.WriteString(w, "Invalid token")
		return
	}
	token, err := gc.getBotToken(issue.InstallationId)
    if err != nil {
		log.Println(err)
		io.WriteString(w, err.Error())
		return
	}
	url := "https://api.github.com/repos/"+issue.Owner+"/"+issue.Repo+"/issues"
	headers := make(map[string]string)
	headers["Authorization"] = "token " + token
	headers["Accept"] = "application/vnd.github.machine-man-preview+json"
	result := new(Issue)
	err = httpPost(url,headers,issue,result)
	if err != nil {
		log.Println(err)
		io.WriteString(w, err.Error())
		return
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		log.Println(err)
		io.WriteString(w, err.Error())
		return
	}
	w.Write(resultBytes)
}

func (gc *GoComment)  OAuth(w http.ResponseWriter, req *http.Request) {
	encoded_url := req.FormValue("url")
	if encoded_url == "" {
		log.Println("url is null")
		io.WriteString(w, "url is null")
		return
	}
	decoded_url, err := base64.StdEncoding.DecodeString(encoded_url)
	if err != nil {
		log.Println(err)
		io.WriteString(w, err.Error())
		return
	}
	code := req.FormValue("code")
	if code == "" {
		log.Println("code is null")
		io.WriteString(w, "code is null")
		return
	}
	log.Println("code:" + code)
	url := "https://github.com/login/oauth/access_token"
	data := new(AuthData)
	data.Code = code
	data.ClientId = gc.ClientId
	data.ClientSecret = gc.ClientSecret
	headers := make(map[string]string)
	headers["Accept"] = "application/json"
	userToken := new(UserToken)
	err = httpPost(url,headers,data,userToken)
	if  err!= nil {
		log.Println(err)
		io.WriteString(w, err.Error())
		return
	}
	if userToken.Error != "" {
		log.Println("oauth error: " + userToken.Error)
		io.WriteString(w, "oauth error: " + userToken.Error)
		return
	}
	log.Println("token:" + userToken.Token)
	redirect_url := string(decoded_url) + "?access_token=" + userToken.Token
	http.Redirect(w,req,redirect_url,302)
}

func httpPost(url string, headers map[string]string, data interface{}, result interface{}) (error) {
	var postData io.Reader
	if data != nil {
		dataBytes, err := json.Marshal(data)
		if err != nil{
			log.Println("httpPost:"+err.Error())
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
		request.Header.Set(key,value)
	}
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Println(err)
		return err
	}
    defer response.Body.Close()
    log.Println("httpPost: StatusCode:" + response.Status)
	resultBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		return err
	}
	log.Println(string(resultBytes))
	return json.Unmarshal(resultBytes, result)
}
 
func main() {
	gc,err := newGoComment()
	if err != nil {
		log.Fatal(err)
		return
	}
    http.HandleFunc("/oauth", gc.OAuth)
    http.HandleFunc("/issue", gc.Issue)
    http.ListenAndServe(":"+strconv.Itoa(gc.Port), nil)
}