package main
 
import (
    "net/http"
    "net/url"
    "encoding/base64"
    "encoding/json"
    "io/ioutil"
    "io"
	"log"
	"strconv"
	"strings"
)

func newGoComment() (*GoComment,error){
	bytes, err := ioutil.ReadFile("./gocomment-oauth.conf")
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	var goComment GoComment
	err = json.Unmarshal(bytes, &goComment)
    if err != nil {
       log.Fatal(err)
       return nil, err
    }
    return &goComment, nil
}

type GoComment struct{
	Client_id, Client_secret string
	Port int
}

func (goComment *GoComment)  IndexHandler(w http.ResponseWriter, req *http.Request) {
	encoded_url := req.FormValue("url")
	if encoded_url == "" {
		log.Println("url is null")
		io.WriteString(w, "url is null")
		return
	}
	decoded_url, err := base64.StdEncoding.DecodeString(encoded_url)
	if err != nil {
		log.Fatal(err)
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
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", goComment.Client_id)
	data.Set("client_secret", goComment.Client_secret)
	resp, err := http.PostForm("https://github.com/login/oauth/access_token",data)
	if err != nil {
		log.Fatal(err)
		io.WriteString(w, err.Error())
		return
	}
	tokenByte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
		io.WriteString(w, err.Error())
		return
	}
	token := string(tokenByte)
	if strings.HasPrefix(token, "error") {
		log.Fatal("oauth error: " + token)
		io.WriteString(w, "oauth error: " + token)
		return
	}
	log.Println("token:" + token)
	redirect_url := string(decoded_url) + "?" + token
	http.Redirect(w,req,redirect_url,302)
}
 
func main() {
	goComment,err := newGoComment()
	if err != nil {
		log.Fatal(err)
		return
	}
    http.HandleFunc("/", goComment.IndexHandler)
    http.ListenAndServe(":"+strconv.Itoa(goComment.Port), nil)
}